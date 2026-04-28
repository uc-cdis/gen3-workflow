from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.status import HTTP_200_OK

from gen3workflow.auth import Auth
from gen3workflow.routes.ga4gh_tes import list_tasks, _cancel_task

router = APIRouter(prefix="/ui")

templates = Jinja2Templates(directory="gen3workflow/templates")

# def get_auth(request):
#     auth = Auth(api_request=request)
#     # from fastapi.security import HTTPAuthorizationCredentials
#     # import os
#     # auth.bearer_token = HTTPAuthorizationCredentials(
#     #     scheme="bearer", credentials=os.environ["TOKEN"]
#     # )
#     return auth


@router.get("", status_code=HTTP_200_OK, response_class=HTMLResponse)
async def ui_list_tasks(request: Request, auth=Depends(Auth)):
    # auth = get_auth(request)
    # TODO find a way to set this instead of going to http://localhost:8080/ui?view=MINIMAL
    # request.query_params = {"view": "MINIMAL"}
    resp = await list_tasks(request, auth)
    tasks = resp.pop("tasks")
    return templates.TemplateResponse(
        request=request,
        name="ui.html",
        context={"tasks": tasks, "is_more": resp.get("next_page_token")},
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
