from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.status import HTTP_200_OK

from gen3workflow.auth import Auth
from gen3workflow.config import config
from gen3workflow.routes.ga4gh_tes import list_tasks, _cancel_task

router = APIRouter(prefix="/ui")

templates = Jinja2Templates(directory="gen3workflow/templates")


def get_auth(request):
    auth = Auth(api_request=request)
    from fastapi.security import HTTPAuthorizationCredentials
    import os

    auth.bearer_token = HTTPAuthorizationCredentials(
        scheme="bearer",
        # credentials="" ,
        credentials=os.environ["TOKEN"],
    )
    return auth


@router.get("", status_code=HTTP_200_OK, response_class=HTMLResponse)
async def ui_list_tasks(request: Request, auth=Depends(Auth)):
    auth = get_auth(request)
    try:
        token_claims = await auth.get_token_claims()
        username = token_claims.get("context", {}).get("user", {}).get("name")
    except Exception:
        username = None
    tasks = []
    is_more = ""
    if username:  # only get the tasks if the user is logged in
        # TODO find a way to set this instead of going to http://localhost:8080/ui?view=MINIMAL
        # request.query_params = {"view": "MINIMAL"}
        resp = await list_tasks(request, auth)
        tasks = resp.pop("tasks")
        is_more = resp.get("next_page_token")
    return templates.TemplateResponse(
        request=request,
        name="ui.html",
        context={
            "hostname": f'https://{config["HOSTNAME"]}',
            "username": username,
            "tasks": tasks,
            "is_more": is_more,
        },
    )


# @router.post(
#     "/cancel/{task_id}",
#     status_code=HTTP_200_OK,
#     response_class=HTMLResponse,
#     include_in_schema=False,
# )
# async def ui_cancel_task(request: Request, task_id: str, auth=Depends(Auth)):
#     # auth = get_auth(request)
#     await _cancel_task(request, task_id, auth)
