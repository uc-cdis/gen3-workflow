from fastapi import APIRouter, Depends, Request, HTTPException
from starlette.status import HTTP_200_OK, HTTP_204_NO_CONTENT, HTTP_404_NOT_FOUND

from gen3workflow import aws_utils, logger
from gen3workflow.auth import Auth


router = APIRouter(prefix="/storage")


@router.get("/info", status_code=HTTP_200_OK)
@router.get("/info/", status_code=HTTP_200_OK, include_in_schema=False)
async def get_storage_info(request: Request, auth=Depends(Auth)) -> dict:
    token_claims = await auth.get_token_claims()
    user_id = token_claims.get("sub")
    logger.info(f"User '{user_id}' getting their own storage info")
    bucket_name, bucket_prefix, bucket_region = aws_utils.create_user_bucket(user_id)
    _, kms_key_arn = aws_utils.get_existing_kms_key_for_bucket(bucket_name)
    return {
        "bucket": bucket_name,
        "workdir": f"s3://{bucket_name}/{bucket_prefix}",
        "region": bucket_region,
        "kms_key_arn": kms_key_arn if kms_key_arn else None,
    }


@router.delete("/user-bucket", status_code=HTTP_204_NO_CONTENT)
@router.delete(
    "/user-bucket/", status_code=HTTP_204_NO_CONTENT, include_in_schema=False
)
async def delete_user_bucket(request: Request, auth=Depends(Auth)) -> None:
    await auth.authorize("delete", ["/services/workflow/gen3-workflow/user-bucket"])

    token_claims = await auth.get_token_claims()
    user_id = token_claims.get("sub")
    logger.info(f"User '{user_id}' deleting their storage bucket")
    deleted_bucket_name = aws_utils.delete_user_bucket(user_id)

    if not deleted_bucket_name:
        raise HTTPException(
            HTTP_404_NOT_FOUND, "Deletion failed: No user bucket found."
        )

    logger.info(
        f"Bucket '{deleted_bucket_name}' for user '{user_id}' deleted successfully"
    )
