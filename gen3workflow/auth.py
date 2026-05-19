import hashlib
import json
from typing import Union

from authutils.token.fastapi import access_token
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from gen3authz.client.arborist.errors import ArboristError
from starlette.requests import Request
from starlette.status import (
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
    HTTP_500_INTERNAL_SERVER_ERROR,
)

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
        """
        Extract the current token string
        """
        if config["MOCK_AUTH"]:
            return "123"

        return (
            self.bearer_token.credentials
            if self.bearer_token and hasattr(self.bearer_token, "credentials")
            else None
        )

    async def get_token_claims(self) -> dict:
        """
        Extract the claims from the curent token
        """
        if config["MOCK_AUTH"]:
            return {"sub": 64, "context": {"user": {"name": "mocked-user"}}}

        if not self.bearer_token:
            err_msg = "Must provide an access token"
            logger.warning(err_msg)
            raise HTTPException(
                HTTP_401_UNAUTHORIZED,
                err_msg,
            )

        try:
            token_claims = await access_token(
                "user", "openid", audience=["gen3", "TES"], purpose="access"
            )(self.bearer_token)
        except Exception as e:
            err_msg = "Could not verify, parse, and/or validate provided access token"
            logger.error(
                f"{err_msg}: {e.detail if hasattr(e, 'detail') else e}",
                exc_info=True,
            )
            raise HTTPException(HTTP_401_UNAUTHORIZED, err_msg)

        return token_claims

    async def get_user_id(self) -> Union[str, None]:
        """
        Parse the user ID from the access token claims
        """
        try:
            token_claims = await self.get_token_claims()
        except Exception:
            return None
        return token_claims.get("sub")

    async def authorize(
        self,
        method: str,
        resources: list,
        throw: bool = True,
    ) -> bool:
        """
        Check whether the current token owner has access to perform the specified action
        """
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
            client_id = token_claims.get("azp")
            logger.error(
                f"Authorization error for user '{user_id}' / client '{client_id}': token must have '{method}' access on {resources} for service 'gen3-workflow'."
            )
            if throw:
                raise HTTPException(
                    HTTP_403_FORBIDDEN,
                    "Permission denied",
                )

        return authorized

    async def grant_user_access_to_their_own_data(
        self, username: str, user_id: str
    ) -> None:
        """
        Ensure the specified user exists in Arborist and has a policy granting them access to their
        own Gen3Workflow tasks and bucket storage.
        Args:
            username (str): The user's Gen3 username
            user_id (str): The user's unique Gen3 ID
        """
        logger.info(
            f"Ensuring user '{user_id}' has access to their own tasks and storage"
        )
        resource_path1 = f"/services/workflow/gen3-workflow/tasks/{user_id}"
        resource1 = {
            "name": user_id,
            "description": f"Represents workflow tasks owned by user '{username}'",
        }

        resource_path2 = f"/services/workflow/gen3-workflow/storage/{user_id}"
        resource2 = {
            "name": user_id,
            "description": f"Represents task storage owned by user '{username}'",
        }

        role_id = "gen3_workflow_admin"
        role = {
            "id": role_id,
            "permissions": [
                {
                    "id": "gen3_workflow_admin_action",
                    "action": {"service": "gen3-workflow", "method": "*"},
                },
            ],
        }

        policy_id = f"gen3_workflow_user_sub_{user_id}"
        policy = {
            "id": policy_id,
            "role_ids": [role_id],
            "resource_paths": [resource_path1, resource_path2],
        }
        policy_hash = hashlib.sha256(
            json.dumps(policy, sort_keys=True).encode("utf-8")
        ).hexdigest()[:10]
        role_hash = hashlib.sha256(
            json.dumps(policy, sort_keys=True).encode("utf-8")
        ).hexdigest()[:10]
        policy_hash = f"{policy_hash}-{role_hash}"
        policy["description"] = (
            f"policy created by gen3-workflow for user '{username}' - HASH={policy_hash}"
        )

        create_or_update_policy = True
        if existing_policy := await self.arborist_client.get_policy(policy_id):
            # the policy already exists, but it may be outdated
            existing_policy_hash = existing_policy["description"].split("HASH=")[-1]
            if policy_hash == existing_policy_hash:
                # the policy is up to date
                create_or_update_policy = False

        grant_policy = True
        try:
            user = await self.arborist_client.get_user(username)
        except ArboristError as e:
            if e.code != 404:
                raise
            # the user doesn't exist: create it
            logger.debug(f"Attempting to create user '{username}' in Arborist")
            await self.arborist_client.create_user_if_not_exist(username)
        else:
            user_policies = (p["policy"] for p in user["policies"])
            if policy_id in user_policies:
                # the user already has this policy
                grant_policy = False

        if create_or_update_policy:
            logger.debug(
                f"Attempting to create resource '{resource_path1}' in Arborist"
            )
            await self.arborist_client.create_resource(
                "/".join(resource_path1.split("/")[:-1]), resource1, create_parents=True
            )

            logger.debug(
                f"Attempting to create resource '{resource_path2}' in Arborist"
            )
            await self.arborist_client.create_resource(
                "/".join(resource_path2.split("/")[:-1]), resource2, create_parents=True
            )

            logger.debug(f"Attempting to update role '{role_id}' in Arborist")
            try:
                await self.arborist_client.update_role(role_id, role)
            except ArboristError as e:
                logger.debug(
                    f"An error occured while updating role '{role_id}': {e}. Attempting to create role instead"
                )
                await self.arborist_client.create_role(role)

            logger.debug(f"Attempting to create policy '{policy_id}' in Arborist")
            await self.arborist_client.create_policy(policy, skip_if_exists=True)

        if grant_policy:
            logger.debug(f"Attempting to grant '{username}' access to '{policy_id}'")
            status_code = await self.arborist_client.grant_user_policy(
                username, policy_id
            )
            if status_code != 204:
                err_msg = "Unable to grant access to user"
                logger.error(f"{err_msg}. Status code: {status_code}")
                raise HTTPException(HTTP_500_INTERNAL_SERVER_ERROR, err_msg)
