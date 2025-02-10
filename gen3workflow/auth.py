from authutils.token.fastapi import access_token
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.requests import Request
from starlette.status import (
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
    HTTP_500_INTERNAL_SERVER_ERROR,
)

from gen3authz.client.arborist.errors import ArboristError

from gen3workflow import logger
from gen3workflow.config import config


# auto_error=False prevents FastAPI from raising a 403 when the request
# is missing an Authorization header. Instead, we want to return a 401
# to signify that we did not receive valid credentials
bearer = HTTPBearer(auto_error=False)


class Auth:
    def __init__(
        self,
        api_request: Request,
        bearer_token: HTTPAuthorizationCredentials = Security(bearer),
    ) -> None:
        self.arborist_client = api_request.app.arborist_client
        self.bearer_token = bearer_token

    def get_access_token(self) -> str:
        if config["MOCK_AUTH"]:
            return "123"

        return (
            self.bearer_token.credentials
            if self.bearer_token and hasattr(self.bearer_token, "credentials")
            else None
        )

    async def get_token_claims(self) -> dict:
        if config["MOCK_AUTH"]:
            return {"sub": 64, "context": {"user": {"name": "mocked-user"}}}

        if not self.bearer_token:
            err_msg = "Must provide an access token"
            logger.error(err_msg)
            raise HTTPException(
                HTTP_401_UNAUTHORIZED,
                err_msg,
            )

        try:
            token_claims = await access_token(
                "user", "openid", audience="openid", purpose="access"
            )(self.bearer_token)
        except Exception as e:
            err_msg = "Could not verify, parse, and/or validate provided access token"
            logger.error(
                f"{err_msg}:\n{e.detail if hasattr(e, 'detail') else e}",
                exc_info=True,
            )
            raise HTTPException(HTTP_401_UNAUTHORIZED, err_msg)

        return token_claims

    async def authorize(
        self,
        method: str,
        resources: list,
        throw: bool = True,
    ) -> bool:
        if config["MOCK_AUTH"]:
            return True

        token = self.get_access_token()
        try:
            authorized = await self.arborist_client.auth_request(
                token, "gen3-workflow", method, resources
            )
        except ArboristError as e:
            logger.error(f"Error while talking to arborist: {e}")
            authorized = False

        if not authorized:
            token_claims = await self.get_token_claims() if token else {}
            user_id = token_claims.get("sub")
            logger.error(
                f"Authorization error for user '{user_id}': token must have '{method}' access on {resources} for service 'gen3-workflow'."
            )
            if throw:
                raise HTTPException(
                    HTTP_403_FORBIDDEN,
                    "Permission denied",
                )

        return authorized

    async def grant_user_access_to_their_own_tasks(self, username, user_id) -> None:
        """
        Ensure the specified user exists in Arborist and has a policy granting them access to their
        own Gen3Workflow tasks ("read" and "delete" access to resource "/users/<user ID>/gen3-workflow/tasks" for service "gen3-workflow").
        Args:
            username (str): The user's Gen3 username
            user_id (str): The user's unique Gen3 ID
        """
        logger.info(f"Ensuring user '{user_id}' has access to their own tasks")
        resource_path = f"/users/{user_id}/gen3-workflow/tasks"
        if await self.authorize(method="read", resources=[resource_path], throw=False):
            # if the user already has access to their own tasks, return early
            return

        logger.debug(f"Attempting to create resource '{resource_path}' in Arborist")
        parent_path = f"/users/{user_id}/gen3-workflow"
        resource = {
            "name": "tasks",
            "description": f"Represents workflow tasks owned by user '{username}'",
        }
        await self.arborist_client.create_resource(
            parent_path, resource, create_parents=True
        )

        role_id = "gen3-workflow_task_owner"
        role = {
            "id": role_id,
            "permissions": [
                {
                    "id": "gen3-workflow-reader",
                    "action": {"service": "gen3-workflow", "method": "read"},
                },
                {
                    "id": "gen3-workflow-deleter",
                    "action": {"service": "gen3-workflow", "method": "delete"},
                },
            ],
        }

        logger.debug(f"Attempting to update role '{role_id}' in Arborist")
        try:
            await self.arborist_client.update_role(role_id, role)
        except ArboristError as e:
            logger.debug(
                f"An error occured while updating role '{role_id}': {e}. Attempting to create role instead"
            )
            await self.arborist_client.create_role(role)

        policy_id = f"gen3-workflow_task_owner_sub-{user_id}"
        logger.debug(f"Attempting to create policy '{policy_id}' in Arborist")
        policy = {
            "id": policy_id,
            "description": f"policy created by gen3-workflow for user '{username}'",
            "role_ids": [role_id],
            "resource_paths": [resource_path],
        }
        await self.arborist_client.create_policy(policy, skip_if_exists=True)

        logger.debug(f"Attempting to create user '{username}' in Arborist")
        await self.arborist_client.create_user_if_not_exist(username)

        # grant the user access to the resource
        logger.debug(f"Attempting to grant '{username}' access to '{policy_id}'")
        status_code = await self.arborist_client.grant_user_policy(username, policy_id)
        if status_code != 204:
            err_msg = "Unable to grant access to user"
            logger.error(f"{err_msg}. Status code: {status_code}")
            raise HTTPException(HTTP_500_INTERNAL_SERVER_ERROR, err_msg)
