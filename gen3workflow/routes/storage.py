from fastapi import APIRouter, Depends, Request
from starlette.status import HTTP_200_OK

from gen3workflow import aws_utils
from gen3workflow.auth import Auth


router = APIRouter(prefix="/storage")


@router.get("/info", status_code=HTTP_200_OK)
async def get_storage_info(request: Request, auth=Depends(Auth)) -> dict:
    token_claims = await auth.get_token_claims()
    user_id = token_claims.get("sub")
    bucket_name, bucket_prefix, bucket_region = aws_utils.create_user_bucket(user_id)
    return {
        "bucket": bucket_name,
        "workdir": f"s3://{bucket_name}/{bucket_prefix}",
        "region": bucket_region,
    }
