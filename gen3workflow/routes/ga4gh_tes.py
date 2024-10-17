"""
Any incoming API calls that match the GA4GH TES spec are redirected to the configured TES server, after preliminary steps such as authorization checks.

GA4GH TES spec:
https://editor.swagger.io/?url=https://raw.githubusercontent.com/ga4gh/task-execution-schemas/develop/openapi/task_execution_service.openapi.yaml
"""

import json

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.status import HTTP_200_OK, HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from gen3workflow import logger
from gen3workflow.auth import Auth
from gen3workflow.config import config


router = APIRouter(prefix="/ga4gh-tes/v1")


async def get_request_body(request: Request):
    # read body as bytes, then decode it as string if necessary
    body_bytes = await request.body()
    try:
        body = body_bytes.decode()
    except UnicodeDecodeError:
        body = str(body_bytes)  # in case of binary data
    return json.loads(body)


@router.get("/service-info", status_code=HTTP_200_OK)
async def service_info(request: Request):
    res = await request.app.async_client.get(f"{config['TES_SERVER_URL']}/service-info")
    if res.status_code != HTTP_200_OK:
        logger.error(f"TES server error: {res.text}")
        raise HTTPException(res.status_code, res.text)
    return res.json()


@router.post("/tasks", status_code=HTTP_200_OK)
async def create_task(request: Request, auth=Depends(Auth)):
    await auth.authorize("create", ["/services/workflow/gen3-workflow/task"])
    body = await get_request_body(request)

    # add the `AUTHZ` tag to the task, so access can be checked by the other endpoints
    user_id = (await auth.get_token_claims()).get("sub")
    if not user_id:
        err_msg = "No user sub in token"
        logger.error(err_msg)
        raise HTTPException(HTTP_401_UNAUTHORIZED, err_msg)
    if "tags" not in body:
        body["tags"] = {}
    body["tags"]["AUTHZ"] = f"/users/{user_id}/gen3-workflow/tasks/TASK_ID_PLACEHOLDER"

    res = await request.app.async_client.post(
        f"{config['TES_SERVER_URL']}/tasks", json=body
    )
    if res.status_code != HTTP_200_OK:
        logger.error(f"TES server error: {res.text}")
        raise HTTPException(res.status_code, res.text)
    return res.json()


@router.get("/tasks", status_code=HTTP_200_OK)
async def list_tasks(request: Request, auth=Depends(Auth)):
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

    # get all the tasks, regardless of access
    # TODO handle `next_page_token`
    res = await request.app.async_client.get(
        f"{config['TES_SERVER_URL']}/tasks", params=query_params
    )
    if res.status_code != HTTP_200_OK:
        logger.error(f"TES server error: {res.text}")
        raise HTTPException(res.status_code, res.text)
    listed_tasks = res.json()

    # ask arborist which resource paths the current user has access to.
    # `user_access` format: { <resource path>: True if user has access, False otherwise }
    all_resource_paths = [
        task.get("tags", {}).get("AUTHZ")
        for task in listed_tasks.get("tasks", [])
        if task.get("tags", {}).get("AUTHZ")
    ]
    user_access = await auth.arborist_client.can_user_access_resources(
        jwt=auth.bearer_token,
        service="gen3-workflow",
        method="read",
        resource_paths=all_resource_paths,
    )

    # filter out tasks the current user does not have access to
    listed_tasks["tasks"] = [
        task
        for task in listed_tasks.get("tasks", [])
        if user_access.get(task.get("tags", {}).get("AUTHZ"))
    ]

    return listed_tasks


@router.get("/tasks/{task_id}", status_code=HTTP_200_OK)
async def get_task(request: Request, task_id: str, auth=Depends(Auth)):
    supported_params = {"view"}
    query_params = {
        k: v for k, v in dict(request.query_params).items() if k in supported_params
    }

    # force the use of "FULL" view so the response includes tags
    original_view = query_params.get("view")
    query_params["view"] = "FULL"

    res = await request.app.async_client.get(
        f"{config['TES_SERVER_URL']}/tasks/{task_id}", params=query_params
    )
    if res.status_code != HTTP_200_OK:
        logger.error(f"TES server error: {res.text}")
        raise HTTPException(res.status_code, res.text)

    # check if this user has access to see this task
    body = res.json()
    authz_path = body.get("tags", {}).get("AUTHZ")
    if not authz_path:
        err_msg = "No authz tag in task body"
        logger.error(f"{err_msg}: {body}")
        raise HTTPException(HTTP_403_FORBIDDEN, err_msg)
    authz_path = authz_path.replace("TASK_ID_PLACEHOLDER", task_id)
    await auth.authorize("create", [authz_path])

    # if the requested view was not "FULL", made a new call with the requested view
    if original_view != "FULL":
        if original_view:
            query_params["view"] = original_view
        else:
            query_params.pop("view")
        res = await request.app.async_client.get(
            f"{config['TES_SERVER_URL']}/tasks/{task_id}", params=query_params
        )
        if res.status_code != HTTP_200_OK:
            logger.error(f"TES server error: {res.text}")
            raise HTTPException(res.status_code, res.text)
        body = res.json()

    return body


@router.post("/tasks/{task_id}:cancel", status_code=HTTP_200_OK)
async def cancel_task(request: Request, task_id: str, auth=Depends(Auth)):
    # check if this user has access to delete this task
    res = await request.app.async_client.get(
        f"{config['TES_SERVER_URL']}/tasks/{task_id}?view=FULL"
    )
    if res.status_code != HTTP_200_OK:
        logger.error(f"TES server error: {res.text}")
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
    res = await request.app.async_client.post(
        f"{config['TES_SERVER_URL']}/tasks/{task_id}:cancel"
    )
    if res.status_code != HTTP_200_OK:
        logger.error(f"TES server error: {res.text}")
        raise HTTPException(res.status_code, res.text)

    return res.json()
