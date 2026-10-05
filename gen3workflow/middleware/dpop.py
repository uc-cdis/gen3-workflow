"""
DPoP (RFC 9449) validation for the endpoints Gen3Workflow exposes to workflow clients.

A DPoP-bound access token carries a `cnf.jkt` claim: the thumbprint of the public key its
holder proved possession of when the token was issued. Every request made with such a token
must come with a fresh DPoP proof signed by the matching private key, so a stolen token is
useless on its own.
"""

import base64
import json
from typing import Awaitable, Callable
from urllib.parse import unquote, urlsplit

from authutils.dpop import validate_dpop_request_async
from authutils.errors import AuthError, InvalidNonceError
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_500_INTERNAL_SERVER_ERROR

from gen3workflow import logger
from gen3workflow.config import (
    config,
    get_dpop_allowed_issuers,
    get_dpop_external_base_url,
    get_dpop_shared_secret,
)
from gen3workflow.routes.ga4gh_tes import router as ga4gh_tes_router
from gen3workflow.routes.s3 import S3_PATH_PREFIX, get_s3_access_key_id_from_auth_header

# The scopes and purpose a DPoP-bound access token must satisfy. These mirror what the
# bearer token path requires (see `Auth.get_token_claims`), so the same token works either way.
REQUIRED_SCOPES = frozenset({"user", "openid"})
REQUIRED_PURPOSE = "access"

# Counter of the requests that reached a protected endpoint without a proof because they carried
# an exempt client's token. Labeled by the `DPOP_PROTECTED_PATHS` prefix rather than the request
# path: an S3 path carries the object key, which would make the label cardinality unbounded.
EXEMPT_REQUESTS_COUNTER = "gen3_workflow_dpop_exempt_requests"

# The only (method, path) pairs on a protected endpoint that accept a request with no credentials
# at all. Every other anonymous request is rejected here, so that an Arborist anonymous policy
# granting access to tasks by mistake does not expose them while DPoP is required.
ANONYMOUS_ENDPOINTS = frozenset(
    {
        ("GET", f"{ga4gh_tes_router.prefix}/service-info"),
        ("GET", f"{ga4gh_tes_router.prefix}/service-info/"),
    }
)


async def dpop_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """
    Validate the DPoP proof of requests to the DPoP-protected endpoints, when `DPOP_REQUIRED`
    is set. Otherwise, every request is passed through untouched.

    Requests that are not to a protected endpoint are passed through untouched. Every other
    request must present a DPoP-bound access token along with a valid proof, except the
    `client_credentials` tokens of the clients listed in `DPOP_EXEMPT_CLIENT_IDS`: such a token is
    never DPoP-bound, and its holder has no key to sign a proof with.

    A DPoP-bound token presented without a proof is always rejected, including one issued to an
    exempt client. So is a proof presented with a token that is not DPoP-bound.

    A request with neither an Authorization header nor a proof is anonymous. It is passed
    through only to the endpoints listed in `ANONYMOUS_ENDPOINTS`, and rejected everywhere else.

    Args:
        request (Request): the incoming HTTP request
        call_next (Callable): function to call (this is handled by FastAPI's middleware support)

    Returns:
        Response: the response from the rest of the app, or an error response if the request
            was rejected.
    """
    if not config["DPOP_REQUIRED"]:
        return await call_next(request)

    auth_header = request.headers.get("authorization", "")
    path_prefix = _get_protected_path_prefix(request.url.path, auth_header)
    if path_prefix is None:
        return await call_next(request)

    access_token = _get_access_token(auth_header)
    dpop_proof = request.headers.get("dpop")

    if (
        not auth_header
        and not dpop_proof
        and (request.method, request.url.path) in ANONYMOUS_ENDPOINTS
    ):
        return await call_next(request)

    if not dpop_proof:
        if access_token and _is_dpop_bound(access_token):
            logger.warning(
                f"Rejecting request to '{request.url.path}': the access token is DPoP-bound but the request has no DPoP proof"
            )
            return _error_response(
                HTTP_401_UNAUTHORIZED,
                "dpop_required",
                "This access token is DPoP-bound and can only be used with a DPoP proof",
            )
        if not (access_token and _is_exempt_client_token(access_token)):
            logger.warning(
                f"Rejecting request to '{request.url.path}': DPoP is required and the request has no DPoP proof"
            )
            return _error_response(
                HTTP_401_UNAUTHORIZED,
                "dpop_required",
                "This endpoint only accepts DPoP-bound access tokens, presented with a DPoP proof",
            )
        _record_exempt_request(request, access_token, path_prefix)
        return await call_next(request)

    if not access_token:
        return _error_response(
            HTTP_401_UNAUTHORIZED,
            "invalid_token",
            "Unable to extract an access token from the Authorization header",
        )

    try:
        _, token_claims, _ = await validate_dpop_request_async(
            dpop_header=dpop_proof,
            access_token=access_token,
            request_method=request.method,
            request_url=_get_url_for_htu(request.url.path, path_prefix, dpop_proof),
            issuers=get_dpop_allowed_issuers(),
            aud=config["VALID_AUTHZ_AUDIENCE"],
            scope=set(REQUIRED_SCOPES),
            purpose=REQUIRED_PURPOSE,
            require_nonce=True,
            secret=get_dpop_shared_secret(),
        )
    except InvalidNonceError as e:
        # The client is expected to retry with the nonce we hand back here. `error_headers`
        # carries both the new nonce and the `WWW-Authenticate` challenge the client looks for.
        logger.info(f"Challenging request to '{request.url.path}' for a DPoP nonce")
        return JSONResponse(status_code=e.code, content=e.json, headers=e.error_headers)
    except ValueError as e:
        # The exact reason is logged, not returned on purpose: these messages quote the `htu` this service
        # expected and the token's `cnf.jkt`, which would hand a caller more info
        # than necessary.
        logger.warning(f"Invalid DPoP proof for '{request.url.path}': {e}")
        return _error_response(
            HTTP_401_UNAUTHORIZED,
            "invalid_dpop_proof",
            "The DPoP proof is missing, malformed, stale or does not match this request",
        )
    except AuthError as e:
        logger.warning(f"Invalid access token for '{request.url.path}': {e}")
        return _error_response(
            HTTP_401_UNAUTHORIZED,
            "invalid_token",
            "The access token is missing, malformed, expired or not accepted here",
        )
    except RuntimeError as e:
        # `authutils` raises this when it has no secret to sign a nonce with
        # This should never happen, but if it does, capture and log it instead of
        # completely dying.
        logger.error(f"Unable to validate the DPoP proof for '{request.url.path}': {e}")
        return _error_response(
            HTTP_500_INTERNAL_SERVER_ERROR,
            "server_error",
            "DPoP is enabled but not configured correctly",
        )

    logger.debug(
        f"Valid DPoP proof for user '{token_claims.get('sub')}' on '{request.url.path}'"
    )

    # The S3 endpoint reads this to refuse a DPoP-bound token that reached it without a
    # validated proof, so that this middleware is not the only thing standing between a stolen
    # bound token and the bucket it is bound for.
    request.state.dpop_validated = True

    if _is_scheme_auth_header(auth_header):
        # Downstream token validation only accepts the `Bearer` scheme. The AWS-signed
        # Authorization header of an S3 request must be left untouched: the S3 endpoint parses
        # the whole signature out of it.
        request.scope["headers"] = _with_bearer_auth_header(
            request.scope["headers"], access_token
        )

    return await call_next(request)


def _get_protected_path_prefix(path: str, auth_header: str) -> str | None:
    """
    Find the configured `DPOP_PROTECTED_PATHS` prefix that covers an incoming request.

    The S3 endpoint is mounted at the root as well as under `S3_PATH_PREFIX`, so an S3 request
    can arrive on a path that matches no prefix, and protecting the root prefix itself would
    cover every unrouted path including `/_status`. On the root mount the Authorization header
    is the only thing identifying an S3 request, so this asks the endpoint's own parser whether
    it can read a token out of the header rather than matching the scheme name. Matching the
    scheme would leave every header format the parser accepts and this function does not - a
    tab after the scheme, an unknown scheme, no scheme at all - unprotected while still
    carrying a usable credential.

    Args:
        path (str): the path of the incoming request, as this service sees it
        auth_header (str): value of the Authorization header

    Returns:
        str | None: the longest matching prefix, or None if the request is not protected
    """
    matches = [
        prefix
        for prefix in config["DPOP_PROTECTED_PATHS"]
        if path == prefix or path.startswith(prefix.rstrip("/") + "/")
    ]
    if matches:
        return max(matches, key=len)

    if S3_PATH_PREFIX in config[
        "DPOP_PROTECTED_PATHS"
    ] and _carries_an_s3_access_key_id(auth_header):
        return S3_PATH_PREFIX
    return None


def _get_url_for_htu(path: str, path_prefix: str, dpop_proof: str) -> str:
    """
    Rebuild the URL the client signed in the proof's `htu` claim.

    The reverse proxy may serve this service under one or more path prefixes that it strips
    before forwarding, so the request path alone does not describe what the client called. The
    query string is left out because `htu` never contains one.

    Some endpoints are reachable at more than one URL, e.g. TES at both `/ga4gh/tes/...` and
    `/workflows/ga4gh/tes/...`. This returns whichever of those URLs the proof's `htu` names, or
    the first one if it names none of them.

    Choosing based on a proof that is not verified yet is safe: every candidate URL is built
    from this service's base URL, a configured prefix and this request's path, so the proof can
    only pick between URLs for this same request. `htu` is percent-decoded before matching
    because `path` already is.

    Args:
        path (str): the path of the incoming request, as this service sees it (decoded)
        path_prefix (str): the matching `DPOP_PROTECTED_PATHS` key
        dpop_proof (str): the encoded DPoP proof presented with the request

    Returns:
        str: the URL to validate `htu` against
    """
    base_url = get_dpop_external_base_url()
    external_paths = [
        f"{external_prefix}{path}"
        for external_prefix in config["DPOP_PROTECTED_PATHS"][path_prefix]
    ]
    signed_htu = _unverified_claims(dpop_proof).get("htu")
    if isinstance(signed_htu, str):
        signed_path = unquote(urlsplit(signed_htu).path)
        if signed_path in external_paths:
            return f"{base_url}{signed_path}"
    # no match: validate against the first form so the proof is rejected with an `htu` mismatch
    return f"{base_url}{external_paths[0]}"


def _get_access_token(auth_header: str) -> str | None:
    """
    Extract the access token from an Authorization header, whichever way it was presented.

    Clients send `DPoP <token>` to the TES endpoints, but the S3 endpoint is called with
    AWS-signed requests that carry the token as the access key ID.

    Args:
        auth_header (str): value of the Authorization header

    Returns:
        str | None: the access token, or None if the header is missing or unparsable
    """
    if not auth_header:
        return None

    if _is_scheme_auth_header(auth_header):
        parts = auth_header.split(maxsplit=1)
        return parts[1].strip() if len(parts) == 2 else None

    try:
        return get_s3_access_key_id_from_auth_header(auth_header)
    except ValueError:
        return None


def _is_scheme_auth_header(auth_header: str) -> bool:
    """
    Check whether an Authorization header carries the access token behind an auth scheme.

    Args:
        auth_header (str): value of the Authorization header

    Returns:
        bool: True if the token follows a `DPoP` or `Bearer` scheme, False for anything else
            (in practice, an AWS signature)
    """
    return auth_header.lower().startswith(("dpop ", "bearer "))


def _carries_an_s3_access_key_id(auth_header: str) -> bool:
    """
    Check whether the S3 endpoint would read an access token out of an Authorization header.

    Defers to the endpoint's own parser so that the set of headers this middleware protects
    cannot drift from the set the endpoint authenticates. A `DPoP` or `Bearer` header is
    excluded because the endpoint refuses those outright.

    Args:
        auth_header (str): value of the Authorization header

    Returns:
        bool: True if the header carries a usable access key ID
    """
    if not auth_header or _is_scheme_auth_header(auth_header):
        return False
    try:
        return bool(get_s3_access_key_id_from_auth_header(auth_header))
    except ValueError:
        return False


def _is_dpop_bound(access_token: str) -> bool:
    """
    Check whether an access token is bound to a DPoP key.

    The token signature is not verified here: this only decides whether a proof is required.
    The proof validation itself re-reads the binding and the token is validated in full.

    Args:
        access_token (str): the encoded access token

    Returns:
        bool: True if the token carries a `cnf.jkt` claim
    """
    claims = _unverified_claims(access_token)
    cnf = claims.get("cnf")
    if not isinstance(cnf, dict):
        return False
    return bool(cnf.get("jkt")) and isinstance(cnf.get("jkt"), str)


def _is_exempt_client_token(access_token: str) -> bool:
    """
    Check whether an access token belongs to a client allowed to skip the DPoP proof.

    Such a token comes from the `client_credentials` flow: it is linked to a client and to no
    user, and is never DPoP-bound, so requiring a proof from it would lock out the worker pods
    that use it. Only the clients listed in `DPOP_EXEMPT_CLIENT_IDS` get that treatment; any
    other client is held to the same requirement as a user.

    The token signature is not verified here: this only decides whether a proof is required. A
    forged token gets no further than the endpoint's own validation, which does verify it.

    Args:
        access_token (str): the encoded access token

    Returns:
        bool: True if the token carries the `azp` claim (the client ID) of an exempt client and
            no `sub` claim
    """
    claims = _unverified_claims(access_token)
    # presence, not truthiness: a token carrying any `sub` is a user's token, and a user is
    # expected to hold a bound one
    if "sub" in claims:
        return False
    return claims.get("azp") in config["DPOP_EXEMPT_CLIENT_IDS"]


def _record_exempt_request(
    request: Request, access_token: str, path_prefix: str
) -> None:
    """
    Log and count a request that reached a protected endpoint without a DPoP proof.

    An exempt token is an ordinary bearer credential, so this is the one place a deployment can
    see the exemption being used, and by which client.

    Args:
        request (Request): the incoming HTTP request
        access_token (str): the exempt client's access token
        path_prefix (str): the matching `DPOP_PROTECTED_PATHS` key
    """
    client_id = _unverified_claims(access_token).get("azp")
    logger.info(
        f"Client '{client_id}' reached '{request.url.path}' with no DPoP proof: exempt by DPOP_EXEMPT_CLIENT_IDS"
    )
    request.app.metrics.increment_counter(
        EXEMPT_REQUESTS_COUNTER,
        {"client_id": client_id, "path_prefix": path_prefix},
        description="Requests accepted on a DPoP-protected endpoint without a DPoP proof, because they carried an exempt client's access token.",
    )


def _unverified_claims(access_token: str) -> dict:
    """
    Decode the claims of a JWT without verifying anything.

    Args:
        access_token (str): the encoded access token

    Returns:
        dict: the decoded claims, or an empty dict if the token is not a decodable JWT
    """
    try:
        payload = access_token.split(".")[1]
        # JWT segments are base64url-encoded without padding
        padding = "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload + padding))
    except Exception:
        return {}
    return claims if isinstance(claims, dict) else {}


def _error_response(
    status_code: int, error: str, error_description: str
) -> JSONResponse:
    """
    Build an RFC 6750 / RFC 9449 style error response.

    Args:
        status_code (int): HTTP status code
        error (str): error code, used in both the body and the `WWW-Authenticate` challenge
        error_description (str): human readable details

    Returns:
        JSONResponse: the error response
    """
    return JSONResponse(
        status_code=status_code,
        content={"error": error, "error_description": error_description},
        headers={"WWW-Authenticate": f'DPoP error="{error}"'},
    )


def _with_bearer_auth_header(
    headers: list[tuple[bytes, bytes]], access_token: str
) -> list[tuple[bytes, bytes]]:
    """
    Replace the Authorization header of an ASGI scope with a `Bearer` one.

    Args:
        headers (list[tuple[bytes, bytes]]): the raw ASGI scope headers
        access_token (str): the validated access token

    Returns:
        list[tuple[bytes, bytes]]: the updated headers
    """
    bearer_header = f"Bearer {access_token}".encode()
    return [
        (key, bearer_header if key.lower() == b"authorization" else value)
        for key, value in headers
    ]
