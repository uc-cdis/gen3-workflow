from gen3authz.client.arborist.errors import ArboristError
from fastapi import APIRouter, Depends, Request, HTTPException
from starlette.status import (
    HTTP_200_OK,
    HTTP_202_ACCEPTED,
    HTTP_204_NO_CONTENT,
    HTTP_401_UNAUTHORIZED,
    HTTP_404_NOT_FOUND,
)

from gen3workflow import aws_utils, logger
from gen3workflow.auth import Auth
from gen3workflow.config import config

router = APIRouter(prefix="/storage")


# TODO: remove the /storage/info path once CI has been updated to use /storage/setup
@router.get("/info", status_code=HTTP_200_OK)
@router.get("/info/", status_code=HTTP_200_OK, include_in_schema=False)
@router.get("/setup", status_code=HTTP_200_OK)
@router.get("/setup/", status_code=HTTP_200_OK, include_in_schema=False)
async def storage_setup(request: Request, auth=Depends(Auth)) -> dict:
    """
    Return details about the current user's storage setup.
    This endpoint also serves as a mandatory "first time setup" for the user's bucket
    and authz.
    """
    token_claims = await auth.get_token_claims()
    user_id = token_claims.get("sub")
    logger.info(f"User '{user_id}' getting their own storage info")
    bucket_name, bucket_prefix, bucket_region, kms_key_arn = (
        aws_utils.create_user_bucket(user_id)
    )

    username = token_claims.get("context", {}).get("user", {}).get("name")
    if not username:
        err_msg = "No context.user.name in token"
        logger.error(err_msg)
        raise HTTPException(HTTP_401_UNAUTHORIZED, err_msg)
    try:
        await auth.grant_user_access_to_their_own_data(
            username=username, user_id=user_id
        )
    except ArboristError as e:
        logger.error(e.message)
        raise HTTPException(e.code, e.message)

    return {
        "bucket": bucket_name,
        "workdir": f"s3://{bucket_name}/{bucket_prefix}",
        "region": bucket_region,
        "kms_key_arn": (
            kms_key_arn if config["KMS_ENCRYPTION_ENABLED"] and kms_key_arn else None
        ),
    }


@router.delete("/user-bucket", status_code=HTTP_202_ACCEPTED)
@router.delete("/user-bucket/", status_code=HTTP_202_ACCEPTED, include_in_schema=False)
async def delete_user_bucket(request: Request, auth=Depends(Auth)) -> None:
    """
    Delete the current user's S3 bucket

    Note:
    Amazon S3 processes bucket deletion asynchronously. The bucket may
    remain visible for a short period until deletion fully propagates.
    """
    token_claims = await auth.get_token_claims()
    user_id = token_claims.get("sub")
    await auth.authorize(
        "delete", [f"/services/workflow/gen3-workflow/tasks/{user_id}"]
    )
    logger.info(f"User '{user_id}' deleting their storage bucket")
    deleted_bucket_name = aws_utils.cleanup_user_bucket(user_id, delete_bucket=True)

    if not deleted_bucket_name:
        raise HTTPException(
            HTTP_404_NOT_FOUND, "Deletion failed: No user bucket found."
        )

    logger.info(
        f"Bucket '{deleted_bucket_name}' for user '{user_id}' scheduled for deletion"
    )

    return {
        "message": "Bucket deletion initiated.",
        "bucket": deleted_bucket_name,
        "details": (
            "Amazon S3 processes bucket deletion asynchronously. "
            "The bucket may remain visible for a short period until "
            "deletion fully propagates across AWS."
        ),
    }


@router.delete("/user-bucket/objects", status_code=HTTP_204_NO_CONTENT)
@router.delete(
    "/user-bucket/objects/", status_code=HTTP_204_NO_CONTENT, include_in_schema=False
)
async def empty_user_bucket(request: Request, auth=Depends(Auth)) -> None:
    """
    Deletes all the objects from current user's S3 bucket
    """
    token_claims = await auth.get_token_claims()
    user_id = token_claims.get("sub")
    await auth.authorize(
        "delete", [f"/services/workflow/gen3-workflow/tasks/{user_id}"]
    )
    logger.info(f"User '{user_id}' emptying their storage bucket")
    deleted_bucket_name = aws_utils.cleanup_user_bucket(user_id)

    if not deleted_bucket_name:
        raise HTTPException(
            HTTP_404_NOT_FOUND, "Deletion failed: No user bucket found."
        )

    logger.info(
        f"All objects remvoved from bucket '{deleted_bucket_name}' for user '{user_id}'"
    )
