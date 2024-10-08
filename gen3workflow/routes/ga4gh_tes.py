"""
Any incoming API calls that match the GA4GH TES spec are redirected to the configured TES server, after preliminary steps such as authorization checks.

GA4GH TES spec:
https://editor.swagger.io/?url=https://raw.githubusercontent.com/ga4gh/task-execution-schemas/develop/openapi/task_execution_service.openapi.yaml
"""

from collections import defaultdict
import json

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.datastructures import QueryParams
from starlette.status import HTTP_200_OK, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED

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


def generate_list_tasks_query_params(
    original_query_params: QueryParams,
    supported_params: list,
    user_id: str,
):
    """
    The `tag_key` and `tag_value` params support setting multiple values, for example:
    `?tag_key=tagA&tag_value=valueA&tag_key=tagB&tag_value=valueB` means that tasks are
    filtered on: `tagA == valueA and tagB == valueB`.
    We need to maintain this support, as well as add the `USER_ID` tag so users can only
    list their own tasks.
    """
    # Convert the query params to a data struct that's easier to work with:
    # [(tag_key, tagA), (tag_value, valueA), (tag_key, tagB), (tag_value, valueB)]
    # becomes {tag_key: [tagA, tagB], tag_value: [valueA, valueB]}
    query_params = defaultdict(list)
    for k, v in original_query_params.multi_items():
        if k in supported_params:  # filter out any unsupported params
            query_params[k].append(v)

    if len(query_params["tag_key"]) != len(query_params["tag_value"]):
        raise Exception(
            HTTP_400_BAD_REQUEST, "Parameters `tag_key` and `tag_value` mismatch"
        )

    # Check if there is already a `USER_ID` tag. If so, its value must be replaced. If not, add one.
    try:
        user_id_tag_index = query_params.get("tag_key", []).index("USER_ID")
    except ValueError:
        query_params["tag_key"].append("USER_ID")
        query_params["tag_value"].append(user_id)
    else:
        query_params["tag_value"][user_id_tag_index] = user_id

    return query_params


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
    user_id = (await auth.get_token_claims()).get("sub")
    query_params = generate_list_tasks_query_params(
        request.query_params, supported_params, user_id
    )
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
