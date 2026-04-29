from dateutil import parser

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.status import HTTP_200_OK

from gen3workflow.auth import Auth
from gen3workflow.config import config
from gen3workflow.routes.ga4gh_tes import list_tasks, cancel_task

router = APIRouter(prefix="/ui")

templates = Jinja2Templates(directory="gen3workflow/templates")


@router.get("", status_code=HTTP_200_OK, response_class=HTMLResponse)
async def tasks_ui(request: Request, auth=Depends(Auth)):
    """
    A UI which allows for basic TES task management
    """
    user_id = await auth.get_user_id()
    username = None
    tasks = []
    is_more = ""

    if user_id:  # only get the tasks if the user is logged in
        token_claims = await auth.get_token_claims()
        username = token_claims.get("context", {}).get("user", {}).get("name")
        resp = await list_tasks(
            Request(
                scope={
                    "app": request.scope["app"],
                    "type": request.scope["type"],
                    "query_string": "view=FULL",
                }
            ),
            auth,
        )
        tasks = resp.pop("tasks")
        is_more = resp.get("next_page_token")

    for i in range(len(tasks)):
        authz_tag = tasks[i]["tags"]["_AUTHZ"]
        tasks[i]["owner_id"] = authz_tag.split(
            "/services/workflow/gen3-workflow/tasks/"
        )[1].split("/")[0]
        simple_date = parser.parse(tasks[i]["creation_time"]).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        tasks[i]["creation_time"] = f"{simple_date} UTC"

    # sort newest to oldest
    tasks.sort(key=lambda x: x["creation_time"], reverse=True)

    return templates.TemplateResponse(
        request=request,
        name="ui.html",
        context={
            "hostname": f'https://{config["HOSTNAME"]}',
            "proxy_prefix": config["PROXY_PREFIX"],
            "user_id": user_id,
            "username": username,
            "tasks": tasks,
            "is_more": is_more,
        },
    )


@router.get("/cancel/{task_id}", status_code=HTTP_200_OK, include_in_schema=False)
async def cancel_task_from_ui(request: Request, task_id: str, auth=Depends(Auth)):
    """
    Shortcut to the `POST /ga4gh/tes/v1/tasks/<task_id>:cancel` endpoint.
    When the UI calls that endpoint directly, the user's credentials are missing.
    There might be a way to fix that, but this was faster.
    """
    await cancel_task(request, task_id, auth)
    return RedirectResponse(f'{config["PROXY_PREFIX"]}/ui')
