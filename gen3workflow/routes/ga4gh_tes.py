"""
Any incoming API calls that match the GA4GH TES spec are redirected to the configured TES server, after preliminary steps such as authorization checks.

GA4GH TES spec:
https://editor.swagger.io/?url=https://raw.githubusercontent.com/ga4gh/task-execution-schemas/develop/openapi/task_execution_service.openapi.yaml
"""

import json

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.status import HTTP_200_OK, HTTP_401_UNAUTHORIZED

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
        raise HTTPException(res.status_code, res.text)
    return res.json()


@router.post("/tasks", status_code=HTTP_200_OK)
async def create_task(request: Request, auth=Depends(Auth)):
    await auth.authorize("create", ["services/workflow/gen3-workflow/task"])
    body = await get_request_body(request)

    # add the USER_ID tag to the task
    if "tags" not in body:
        body["tags"] = {}
    body["tags"]["USER_ID"] = (await auth.get_token_claims()).get("sub")
    if not body["tags"]["USER_ID"]:
        raise HTTPException(HTTP_401_UNAUTHORIZED, "No user sub in token")

    res = await request.app.async_client.post(
        f"{config['TES_SERVER_URL']}/tasks", json=body
    )
    if res.status_code != HTTP_200_OK:
        raise HTTPException(res.status_code, res.text)
    return res.json()


@router.get("/tasks", status_code=HTTP_200_OK)
async def list_tasks(request: Request):
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
    res = await request.app.async_client.get(
        f"{config['TES_SERVER_URL']}/tasks", params=query_params
    )
    if res.status_code != HTTP_200_OK:
        raise HTTPException(res.status_code, res.text)
    return res.json()


@router.get("/tasks/{task_id}", status_code=HTTP_200_OK)
async def get_task(request: Request, task_id: str):
    supported_params = {"view"}
    query_params = {
        k: v for k, v in dict(request.query_params).items() if k in supported_params
    }
    res = await request.app.async_client.get(
        f"{config['TES_SERVER_URL']}/tasks/{task_id}", params=query_params
    )
    if res.status_code != HTTP_200_OK:
        raise HTTPException(res.status_code, res.text)
    return res.json()


@router.post("/tasks/{task_id}:cancel", status_code=HTTP_200_OK)
async def cancel_task(request: Request, task_id: str):
    res = await request.app.async_client.post(
        f"{config['TES_SERVER_URL']}/tasks/{task_id}:cancel"
    )
    if res.status_code != HTTP_200_OK:
        raise HTTPException(res.status_code, res.text)
    return res.json()
