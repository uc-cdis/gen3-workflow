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

from authutils.dpop import validate_dpop_request_async
from authutils.errors import AuthError, InvalidNonceError
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_500_INTERNAL_SERVER_ERROR

from gen3workflow import logger
from gen3workflow.config import (
    config,
    get_dpop_allowed_issuers,
    get_dpop_shared_secret,
)
from gen3workflow.routes.s3 import get_access_key_id_from_auth_header

# The scopes and purpose a DPoP-bound access token must satisfy. These mirror what the
# bearer token path requires (see `Auth.get_token_claims`), so the same token works either way.
REQUIRED_SCOPES = frozenset({"user", "openid"})
REQUIRED_PURPOSE = "access"


async def dpop_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """
    Validate the DPoP proof of requests to the DPoP-protected endpoints.

    Requests that are not to a protected endpoint are passed through untouched. So are requests
    that carry neither a DPoP proof nor a DPoP-bound token, unless `DPOP_REQUIRED` is set.
    Tokens issued through the `client_credentials` flow are exempt from `DPOP_REQUIRED`: that is
    how worker pods reach these endpoints, since that flow already does client authentication.

    A proof presented with a token that is not DPoP-bound is always rejected, whatever
    `DPOP_REQUIRED` is set to. So is a DPoP-bound token presented without a proof, including one
    issued to a client.

    Args:
        request (Request): the incoming HTTP request
        call_next (Callable): function to call (this is handled by FastAPI's middleware support)

    Returns:
        Response: the response from the rest of the app, or an error response if the request
            was rejected.
    """
    if not config["DPOP_ENABLED"]:
        return await call_next(request)

    path_prefix = _get_protected_path_prefix(request.url.path)
    if path_prefix is None:
        return await call_next(request)

    auth_header = request.headers.get("authorization", "")
    access_token = _get_access_token(auth_header)
    dpop_proof = request.headers.get("dpop")

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
        if config["DPOP_REQUIRED"] and not (
            access_token and _is_client_credentials_token(access_token)
        ):
            logger.warning(
                f"Rejecting request to '{request.url.path}': DPoP is required and the request has no DPoP proof"
            )
            return _error_response(
                HTTP_401_UNAUTHORIZED,
                "dpop_required",
                "This endpoint only accepts DPoP-bound access tokens, presented with a DPoP proof",
            )
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
            request_url=_get_url(request.url.path, path_prefix),
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
        logger.warning(f"Invalid DPoP proof for '{request.url.path}': {e}")
        return _error_response(HTTP_401_UNAUTHORIZED, "invalid_dpop_proof", str(e))
    except AuthError as e:
        logger.warning(f"Invalid access token for '{request.url.path}': {e}")
        return _error_response(HTTP_401_UNAUTHORIZED, "invalid_token", str(e))
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

    if _is_scheme_auth_header(auth_header):
        # Downstream token validation only accepts the `Bearer` scheme. The AWS-signed
        # Authorization header of an S3 request must be left untouched: the S3 endpoint parses
        # the whole signature out of it.
        request.scope["headers"] = _with_bearer_auth_header(
            request.scope["headers"], access_token
        )

    return await call_next(request)


def _get_protected_path_prefix(path: str) -> str | None:
    """
    Find the configured `DPOP_PROTECTED_PATHS` prefix that covers the requested path.

    Args:
        path (str): the path of the incoming request, as this service sees it

    Returns:
        str | None: the longest matching prefix, or None if the path is not protected
    """
    matches = [
        prefix
        for prefix in config["DPOP_PROTECTED_PATHS"]
        if path == prefix or path.startswith(prefix.rstrip("/") + "/")
    ]
    return max(matches, key=len) if matches else None


def _get_url(path: str, path_prefix: str) -> str:
    """
    Rebuild the URL the client signed in the proof's `htu` claim.

    The reverse proxy may serve this service under a path prefix that it strips before
    forwarding, so the request path alone does not describe what the client called. The query
    string is left out because `htu` never contains one.

    Args:
        path (str): the path of the incoming request, as this service sees it
        path_prefix (str): the matching `DPOP_PROTECTED_PATHS` key

    Returns:
        str: the URL to validate `htu` against
    """
    base_url = config["DPOP_EXTERNAL_BASE_URL"] or f"https://{config['HOSTNAME']}"
    external_prefix = config["DPOP_PROTECTED_PATHS"][path_prefix]
    return f"{base_url.rstrip('/')}{external_prefix}{path}"


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
        access_key_id = get_access_key_id_from_auth_header(auth_header)
    except ValueError:
        return None
    # A client acting on behalf of a user appends the user ID to its token
    return access_key_id.split(";userId=")[0]


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


def _is_client_credentials_token(access_token: str) -> bool:
    """
    Check whether an access token was issued through the `client_credentials` flow.

    Such a token is linked to a client and to no user, and is never DPoP-bound, so requiring a
    proof from it would lock out the worker pods that use it.

    The token signature is not verified here: this only decides whether a proof is required. A
    forged token gets no further than the endpoint's own validation, which does verify it.

    Args:
        access_token (str): the encoded access token

    Returns:
        bool: True if the token carries an `azp` claim (the client ID) and no `sub` claim
    """
    claims = _unverified_claims(access_token)
    return bool(claims.get("azp")) and not claims.get("sub")


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
