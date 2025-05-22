"""
Any incoming API calls that match the GA4GH TES spec are redirected to the configured TES server, after preliminary steps such as authorization checks.

GA4GH TES spec:
https://editor.swagger.io/?url=https://raw.githubusercontent.com/ga4gh/task-execution-schemas/develop/openapi/task_execution_service.openapi.yaml
"""

import json
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from gen3authz.client.arborist.errors import ArboristError
from starlette.status import HTTP_200_OK, HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from gen3workflow import logger
from gen3workflow.auth import Auth
from gen3workflow.config import config


router = APIRouter(prefix="/ga4gh/tes/v1")


async def get_request_body(request: Request):
    # read body as bytes, then decode it as string if necessary
    body_bytes = await request.body()
    try:
        body = body_bytes.decode()
    except UnicodeDecodeError:
        body = str(body_bytes)  # in case of binary data
    return json.loads(body)


@router.get("/service-info", status_code=HTTP_200_OK)
async def service_info(request: Request, auth=Depends(Auth)) -> dict:
    try:
        token_claims = await auth.get_token_claims()
    except Exception:
        token_claims = {}
    user_id = token_claims.get("sub")
    logger.info(f"User '{user_id}' getting TES service info")

    url = f"{config['TES_SERVER_URL']}/service-info"
    res = await request.app.async_client.get(url)
    if res.status_code != HTTP_200_OK:
        logger.error(f"TES server error at 'GET {url}': {res.status_code} {res.text}")
        raise HTTPException(res.status_code, res.text)
    return res.json()


def get_non_allowed_images(images: set, username: str) -> set:
    """
    Returns a set of images that do not match any whitelisted patterns.

    Parameters:
    - images (set): Set of images to check.
    - username (str): Username to substitute in the whitelisted patterns.

    Returns:
    - set: Set of images not allowed based on whitelisted patterns.
    """

    # Update each whitelisted image to a regex with updated {username} value with an actual username
    # and `*` with `.*` to match any sequence of characters, storing the resulting patterns in a set
    whitelisted_images_regex = {
        image.replace("{username}", username).replace("*", ".*")
        for image in config["TASK_IMAGE_WHITELIST"]
    }
    # Add the image to non_allowed_images if it does not match any pattern in whitelisted_images_regex
    non_allowed_images = {
        image
        for image in images
        if not any(
            re.match(f"^{pattern}$", image) for pattern in whitelisted_images_regex
        )
    }

    # Returns a set of all the images that are not from the list of whitelisted images.
    return non_allowed_images


@router.post("/tasks", status_code=HTTP_200_OK)
async def create_task(request: Request, auth=Depends(Auth)) -> dict:
    await auth.authorize("create", ["/services/workflow/gen3-workflow/tasks"])

    body = await get_request_body(request)

    # add the `AUTHZ` tag to the task, so access can be checked by the other endpoints
    token_claims = await auth.get_token_claims()
    user_id = token_claims.get("sub")
    if not user_id:
        err_msg = "No user sub in token"
        logger.error(err_msg)
        raise HTTPException(HTTP_401_UNAUTHORIZED, err_msg)
    username = token_claims.get("context", {}).get("user", {}).get("name")
    if not username:
        err_msg = "No context.user.name in token"
        logger.error(err_msg)
        raise HTTPException(HTTP_401_UNAUTHORIZED, err_msg)
    logger.info(f"User '{user_id}' creating TES task")

    # Fetch the list of images from request body as a set
    images_from_request = {
        executor["image"]
        for executor in body.get("executors", [])
        if "image" in executor
    }

    invalid_images = get_non_allowed_images(images_from_request, username)
    if invalid_images:
        err_msg = f"The specified images are not allowed: {list(invalid_images)}"
        logger.error(f"{err_msg}. Allowed images: {config['TASK_IMAGE_WHITELIST']}")
        raise HTTPException(HTTP_403_FORBIDDEN, err_msg)

    if "tags" not in body:
        body["tags"] = {}
    # TODO unit test: user can't set USER_ID tag manually
    # TODO raise an error if it's set, and explain it's an internal tag. Same for AUTHZ tag
    # body["tags"]["USER_ID"] = user_id  # used by the funnel plugin to identify the user
    body["tags"]["AUTHZ"] = f"/users/{user_id}/gen3-workflow/tasks/TASK_ID_PLACEHOLDER"

    url = f"{config['TES_SERVER_URL']}/tasks"
    res = await request.app.async_client.post(
        url,
        json=body,
        headers={"Authorization": f"bearer {auth.bearer_token.credentials}"},
    )
    if res.status_code != HTTP_200_OK:
        logger.error(f"TES server error at 'POST {url}': {res.status_code} {res.text}")
        raise HTTPException(res.status_code, res.text)

    try:
        await auth.grant_user_access_to_their_own_tasks(
            username=username, user_id=user_id
        )
    except ArboristError as e:
        logger.error(e.message)
        raise HTTPException(e.code, e.message)

    return res.json()


def apply_view_to_task(view: str, task: dict) -> dict:
    """
    We always set the view to "FULL" when making get/list requests to the TES server, because we
    need to get the AUTHZ tag in order to check whether users have access. This function applies
    the view that was originally requested by removing fields according to the TES spec.

    Args:
        view (str): view to apply (FULL, MINIMAL or BASIC). If None, MINIMAL is applied.
        task (dict): TES task
    Returns:
        dict: TES task with applied view
    """
    if view == "FULL":
        return task

    if view == "BASIC":
        return {"id": task.get("id"), "state": task.get("state")}

    # otherwise, view == None or "MINIMAL", which is the default according to the TES spec
    for i in range(len(task.get("executors", []))):
        task["executors"][i].pop("stderr", None)
        task["executors"][i].pop("stdin", None)
    for i in range(len(task.get("inputs", []))):
        task["inputs"][i].pop("content", None)
    for i in range(len(task.get("logs", []))):
        task["logs"][i].pop("system_logs", None)

    return task


@router.get("/tasks", status_code=HTTP_200_OK)
async def list_tasks(request: Request, auth=Depends(Auth)) -> dict:
    try:
        token_claims = await auth.get_token_claims()
    except Exception:
        token_claims = {}
    user_id = token_claims.get("sub")
    logger.info(f"User '{user_id}' listing TES tasks")

    supported_params = {
        "name_prefix",
        "state",
        "tag_key",
        "tag_value",
        "page_size",
        "page_token",
        "view",
    }
    query_params = {
        k: v for k, v in dict(request.query_params).items() if k in supported_params
    }

    # force the use of "FULL" view so the response includes tags
    requested_view = query_params.get("view")
    query_params["view"] = "FULL"

    # get all the tasks, regardless of access
    url = f"{config['TES_SERVER_URL']}/tasks"
    res = await request.app.async_client.get(url, params=query_params)
    if res.status_code != HTTP_200_OK:
        logger.error(f"TES server error at 'GET {url}': {res.status_code} {res.text}")
        raise HTTPException(res.status_code, res.text)
    listed_tasks = res.json()

    # get all the tasks' authz resource paths, replacing the task ID placeholder with the actual ID
    all_resource_paths = set()
    for task in listed_tasks.get("tasks", []):
        if task.get("tags", {}).get("AUTHZ"):
            task["tags"]["AUTHZ"] = task["tags"]["AUTHZ"].replace(
                "TASK_ID_PLACEHOLDER", task.get("id")
            )
            all_resource_paths.add(task["tags"]["AUTHZ"])

    # ask arborist which resource paths the current user has access to.
    # `user_access` format: { <resource path>: True if user has access, False otherwise }
    try:
        user_access = await auth.arborist_client.can_user_access_resources(
            jwt=auth.get_access_token(),
            resources={
                r: {"service": "gen3-workflow", "method": "read"}
                for r in all_resource_paths
            },
        )
    except ArboristError as e:
        logger.error(e.message)
        raise HTTPException(e.code, e.message)

    # filter out tasks the current user does not have access to
    listed_tasks["tasks"] = [
        apply_view_to_task(requested_view, task)
        for task in listed_tasks.get("tasks", [])
        if user_access.get(task.get("tags", {}).get("AUTHZ"))
    ]

    return listed_tasks


@router.get("/tasks/{task_id}", status_code=HTTP_200_OK)
async def get_task(request: Request, task_id: str, auth=Depends(Auth)) -> dict:
    try:
        token_claims = await auth.get_token_claims()
    except Exception:
        token_claims = {}
    user_id = token_claims.get("sub")
    logger.info(f"User '{user_id}' getting TES task '{task_id}'")

    supported_params = {"view"}
    query_params = {
        k: v for k, v in dict(request.query_params).items() if k in supported_params
    }

    # force the use of "FULL" view so the response includes tags
    requested_view = query_params.get("view")
    query_params["view"] = "FULL"

    url = f"{config['TES_SERVER_URL']}/tasks/{task_id}"
    res = await request.app.async_client.get(url, params=query_params)
    if res.status_code != HTTP_200_OK:
        logger.error(f"TES server error at 'GET {url}': {res.status_code} {res.text}")
        raise HTTPException(res.status_code, res.text)

    # check if this user has access to see this task
    body = res.json()
    authz_path = body.get("tags", {}).get("AUTHZ")
    if not authz_path:
        err_msg = "No authz tag in task body"
        logger.error(f"{err_msg}: {body}")
        raise HTTPException(HTTP_403_FORBIDDEN, err_msg)
    body["tags"]["AUTHZ"] = authz_path.replace("TASK_ID_PLACEHOLDER", task_id)
    await auth.authorize("read", [body["tags"]["AUTHZ"]])

    return apply_view_to_task(requested_view, body)


@router.post("/tasks/{task_id}:cancel", status_code=HTTP_200_OK)
async def cancel_task(request: Request, task_id: str, auth=Depends(Auth)) -> dict:
    try:
        token_claims = await auth.get_token_claims()
    except Exception:
        token_claims = {}
    user_id = token_claims.get("sub")
    logger.info(f"User '{user_id}' canceling TES task '{task_id}'")

    # check if this user has access to delete this task
    url = f"{config['TES_SERVER_URL']}/tasks/{task_id}?view=FULL"
    res = await request.app.async_client.get(url)
    if res.status_code != HTTP_200_OK:
        logger.error(f"TES server error at 'GET {url}': {res.status_code} {res.text}")
        raise HTTPException(res.status_code, res.text)
    body = res.json()
    authz_path = body.get("tags", {}).get("AUTHZ")
    if not authz_path:
        err_msg = "No authz tag in task body"
        logger.error(f"{err_msg}: {body}")
        raise HTTPException(HTTP_403_FORBIDDEN, err_msg)
    authz_path = authz_path.replace("TASK_ID_PLACEHOLDER", task_id)
    await auth.authorize("delete", [authz_path])

    # the user has access: delete the task
    url = f"{config['TES_SERVER_URL']}/tasks/{task_id}:cancel"
    res = await request.app.async_client.post(url)
    if res.status_code != HTTP_200_OK:
        logger.error(f"TES server error at 'POST {url}': {res.status_code} {res.text}")
        raise HTTPException(res.status_code, res.text)

    return res.json()
