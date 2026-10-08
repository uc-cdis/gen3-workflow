"""
Stubbed versions of the endpoints that depend on the TES server, AWS or S3. See
`DEBUG_STUB_EXTERNAL_SERVICES`.

This is intended for testing workflow and auth flows locally without needing to setup Funnel or S3,
in cases where you don't care that the actual workflow / task does anything.

`get_app` mounts these routers in place of the real ones, once at startup, so no real endpoint
ever checks the setting and no stubbed response can be served while it is off. Each router here
must expose exactly the routes of the real router it replaces: a route missing here would
silently reach the real external services in stub mode.

The stubs authenticate and authorize requests the same way the real endpoints do, against the
real auth service and Arborist (or `MOCK_AUTH`), so stub mode exercises the real auth path. Only
the calls to the TES server, AWS and S3 are replaced: no task runs and no object is stored.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from gen3authz.client.arborist.errors import ArboristError
from starlette.responses import Response
from starlette.status import (
    HTTP_200_OK,
    HTTP_202_ACCEPTED,
    HTTP_204_NO_CONTENT,
    HTTP_401_UNAUTHORIZED,
)

from gen3workflow import logger
from gen3workflow.auth import Auth
from gen3workflow.aws import aws_utils
from gen3workflow.config import config
from gen3workflow.routes.ga4gh_tes import router as ga4gh_tes_router
from gen3workflow.routes.s3 import (
    S3_PATH_PREFIX,
    authorize_s3_request,
    is_list_buckets_request,
    list_buckets_response,
)
from gen3workflow.routes.storage import (
    authorize_own_storage_deletion,
)
from gen3workflow.routes.storage import router as storage_router

stubbed_ga4gh_tes_router = APIRouter(prefix=ga4gh_tes_router.prefix)
stubbed_s3_root_router = APIRouter(include_in_schema=False)
stubbed_s3_router = APIRouter(prefix=S3_PATH_PREFIX)
stubbed_status_router = APIRouter()
stubbed_storage_router = APIRouter(prefix=storage_router.prefix)

S3_METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "HEAD"]

STUBBED_TES_SERVICE_INFO = {
    "id": "stubbed-tes-server",
    "name": "Stubbed TES server",
    "type": {"group": "org.ga4gh", "artifact": "tes", "version": "1.1"},
    "organization": {"name": "Gen3Workflow", "url": "https://gen3.org"},
    "version": "1.1",
}

STUBBED_LIST_BUCKET_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    "<Name>{bucket}</Name><Prefix></Prefix><Marker></Marker><MaxKeys>250</MaxKeys>"
    "<EncodingType>url</EncodingType><IsTruncated>false</IsTruncated>"
    "</ListBucketResult>"
)


@stubbed_ga4gh_tes_router.get("/service-info", status_code=HTTP_200_OK)
@stubbed_ga4gh_tes_router.get(
    "/service-info/", status_code=HTTP_200_OK, include_in_schema=False
)
async def stubbed_service_info(auth=Depends(Auth)) -> dict:
    """
    Stubbed `GET /ga4gh/tes/v1/service-info`: describes a TES server that does not exist. Like
    the real endpoint, it does not require an access token.
    """
    await auth.get_user_id()
    _log_stubbed_request("GET /service-info")
    return STUBBED_TES_SERVICE_INFO


@stubbed_ga4gh_tes_router.post("/tasks", status_code=HTTP_200_OK)
@stubbed_ga4gh_tes_router.post(
    "/tasks/", status_code=HTTP_200_OK, include_in_schema=False
)
async def stubbed_create_task(auth=Depends(Auth)) -> dict:
    """
    Stubbed `POST /ga4gh/tes/v1/tasks`: returns a task ID no TES server ever issued, for a task
    that does not exist.
    """
    # the real endpoint rejects an invalid token when it reads the token's claims for the task
    # tags, after authorizing: without this, a missing token would only be caught by Arborist
    await auth.get_token_claims()
    await auth.authorize("create", ["/services/workflow/gen3-workflow/tasks"])
    _log_stubbed_request("POST /tasks")
    return {"id": f"stubbed-task-{uuid.uuid4().hex[:8]}"}


@stubbed_ga4gh_tes_router.get("/tasks", status_code=HTTP_200_OK)
@stubbed_ga4gh_tes_router.get(
    "/tasks/", status_code=HTTP_200_OK, include_in_schema=False
)
async def stubbed_list_tasks(auth=Depends(Auth)) -> dict:
    """
    Stubbed `GET /ga4gh/tes/v1/tasks`: the user never has any task.
    """
    await auth.get_token_claims()
    _log_stubbed_request("GET /tasks")
    return {"tasks": []}


@stubbed_ga4gh_tes_router.get("/tasks/{task_id}", status_code=HTTP_200_OK)
@stubbed_ga4gh_tes_router.get(
    "/tasks/{task_id}/", status_code=HTTP_200_OK, include_in_schema=False
)
async def stubbed_get_task(task_id: str, auth=Depends(Auth)) -> dict:
    """
    Stubbed `GET /ga4gh/tes/v1/tasks/{task_id}`: the requested task, always reported as complete.
    """
    await auth.authorize("read", [await _get_task_authz_path(auth, task_id)])
    _log_stubbed_request(f"GET /tasks/{task_id}")
    return {"id": task_id, "state": "COMPLETE"}


@stubbed_ga4gh_tes_router.post("/tasks/{task_id}:cancel", status_code=HTTP_200_OK)
@stubbed_ga4gh_tes_router.post(
    "/tasks/{task_id}/:cancel", status_code=HTTP_200_OK, include_in_schema=False
)
async def stubbed_cancel_task(task_id: str, auth=Depends(Auth)) -> dict:
    """
    Stubbed `POST /ga4gh/tes/v1/tasks/{task_id}:cancel`: reports the cancellation as successful.
    """
    await auth.authorize("delete", [await _get_task_authz_path(auth, task_id)])
    _log_stubbed_request(f"POST /tasks/{task_id}:cancel")
    return {}


@stubbed_s3_root_router.api_route("/{path:path}", methods=S3_METHODS)
@stubbed_s3_router.api_route("/{path:path}", methods=S3_METHODS)
async def stubbed_s3_endpoint(path: str, request: Request) -> Response:
    """
    Stubbed S3 endpoint: answers with a response plausible enough for an S3 client to accept,
    after the same authentication, authorization and bucket checks as the real endpoint.
    """
    user_bucket = await authorize_s3_request(request, path)
    if is_list_buckets_request(request.method, path):
        return list_buckets_response(user_bucket)

    _log_stubbed_request(f"{request.method} /{path}")
    if request.method == "DELETE":
        return Response(status_code=HTTP_204_NO_CONTENT)
    if request.method in ("PUT", "POST"):
        return Response(status_code=HTTP_200_OK, headers={"ETag": '"stubbed-etag"'})

    bucket_and_key = path.split("?")[0].strip("/")
    if "/" in bucket_and_key:  # the request is about a specific object
        return Response(status_code=HTTP_200_OK)
    return Response(
        content=STUBBED_LIST_BUCKET_XML.format(bucket=bucket_and_key),
        status_code=HTTP_200_OK,
        media_type="application/xml",
    )


@stubbed_storage_router.get("/setup", status_code=HTTP_200_OK)
@stubbed_storage_router.get("/setup/", status_code=HTTP_200_OK, include_in_schema=False)
async def stubbed_storage_setup(auth=Depends(Auth)) -> dict:
    """
    Stubbed `GET /storage/setup`: reports the bucket the user would have, without creating it,
    but grants the user access to their own tasks and storage in Arborist like the real endpoint
    does. The other stubs authorize against those grants, so this is still the mandatory first
    call.
    """
    token_claims = await auth.get_token_claims()
    user_id = token_claims.get("sub")
    username = token_claims.get("context", {}).get("user", {}).get("name")
    if not username:
        err_msg = "No context.user.name in token"
        logger.error(err_msg)
        raise HTTPException(HTTP_401_UNAUTHORIZED, err_msg)

    await auth.authorize("create", ["/services/workflow/gen3-workflow/tasks"])

    try:
        await auth.grant_user_access_to_their_own_data(
            username=username, user_id=user_id
        )
    except ArboristError as e:
        logger.error(e.message)
        raise HTTPException(e.code, e.message)

    _log_stubbed_request("GET /storage/setup")
    bucket_name = aws_utils.get_safe_name_from_hostname(user_id)
    return {
        "bucket": bucket_name,
        "workdir": f"s3://{bucket_name}/ga4gh-tes",
        "region": config["USER_BUCKETS_REGION"],
    }


@stubbed_storage_router.delete("/user-bucket", status_code=HTTP_202_ACCEPTED)
@stubbed_storage_router.delete(
    "/user-bucket/", status_code=HTTP_202_ACCEPTED, include_in_schema=False
)
async def stubbed_delete_user_bucket(auth=Depends(Auth)) -> dict:
    """
    Stubbed `DELETE /storage/user-bucket`: reports the deletion as initiated.
    """
    user_id = await authorize_own_storage_deletion(auth)
    _log_stubbed_request("DELETE /storage/user-bucket")
    return {
        "message": "Bucket deletion initiated.",
        "bucket": aws_utils.get_safe_name_from_hostname(user_id),
    }


@stubbed_storage_router.delete("/user-bucket/objects", status_code=HTTP_204_NO_CONTENT)
@stubbed_storage_router.delete(
    "/user-bucket/objects/", status_code=HTTP_204_NO_CONTENT, include_in_schema=False
)
async def stubbed_empty_user_bucket(auth=Depends(Auth)) -> None:
    """
    Stubbed `DELETE /storage/user-bucket/objects`: reports the bucket as emptied.
    """
    await authorize_own_storage_deletion(auth)
    _log_stubbed_request("DELETE /storage/user-bucket/objects")


@stubbed_status_router.get("/_status")
@stubbed_status_router.get("/_status/", include_in_schema=False)
async def stubbed_get_status() -> dict:
    """
    Stubbed `GET /_status`: reports OK without contacting the TES server, which is not expected
    to be running, so that probes neither take the pod out of service nor log a connection error
    each.
    """
    return dict(status="OK")


async def _get_task_authz_path(auth: Auth, task_id: str) -> str:
    """
    Build the authz resource path the real endpoints read from a task's `_AUTHZ` tag, as task
    creation would have set it for a task owned by the caller.

    Args:
        auth (Auth): the request's auth instance
        task_id (str): the requested task ID

    Returns:
        str: the task's authz resource path
    """
    user_id = (await auth.get_token_claims()).get("sub")
    return f"/services/workflow/gen3-workflow/tasks/{user_id}/{task_id}"


def _log_stubbed_request(endpoint: str) -> None:
    """
    Log that a request got a stubbed response, so that a stubbed deployment cannot be mistaken
    for a working one.

    Args:
        endpoint (str): the endpoint being stubbed
    """
    logger.warning(
        f"DEBUG MODE: returning a stubbed response for '{endpoint}' instead of contacting the "
        "TES server, AWS or S3. 'DEBUG_STUB_EXTERNAL_SERVICES' must NOT be enabled in production!"
    )
