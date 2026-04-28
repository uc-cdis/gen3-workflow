from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.status import HTTP_200_OK

from gen3workflow.auth import Auth
from gen3workflow.config import config
from gen3workflow.routes.ga4gh_tes import list_tasks

router = APIRouter(prefix="/ui")

templates = Jinja2Templates(directory="gen3workflow/templates")


@router.get("", status_code=HTTP_200_OK, response_class=HTMLResponse)
async def ui_list_tasks(request: Request, auth=Depends(Auth)):
    auth = Auth(api_request=request)
    try:
        token_claims = await auth.get_token_claims()
        username = token_claims.get("context", {}).get("user", {}).get("name")
    except Exception:
        username = None
    tasks = []
    is_more = ""
    if username:  # only get the tasks if the user is logged in
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
