from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.status import (
    HTTP_200_OK,
    HTTP_201_CREATED,
    HTTP_204_NO_CONTENT,
    HTTP_400_BAD_REQUEST,
)

from gen3workflow import aws_utils, logger
from gen3workflow.auth import Auth
from gen3workflow.config import config


router = APIRouter(prefix="/storage")


@router.get("/info", status_code=HTTP_200_OK)
async def get_storage_info(request: Request, auth=Depends(Auth)):
    token_claims = await auth.get_token_claims()
    user_id = token_claims.get("sub")
    bucket_name, bucket_prefix, bucket_region = aws_utils.create_user_bucket(user_id)
    return {
        "bucket": bucket_name,
        "workdir": f"s3://{bucket_name}/{bucket_prefix}",
        "region": bucket_region,
    }


@router.post("/credentials", status_code=HTTP_201_CREATED)
async def generate_user_key(request: Request, auth=Depends(Auth)):
    token_claims = await auth.get_token_claims()
    user_id = token_claims.get("sub")

    existing_keys = aws_utils.list_iam_user_keys(user_id)
    if len(existing_keys) >= config["MAX_IAM_KEYS_PER_USER"]:
        err_msg = f"Too many existing keys: only {config['MAX_IAM_KEYS_PER_USER']} are allowed per user. Delete an existing key before creating a new one"
        logger.error(err_msg)
        raise HTTPException(HTTP_400_BAD_REQUEST, err_msg)

    key_id, key_secret = aws_utils.create_iam_user_and_key(user_id)
    return {
        "aws_key_id": key_id,
        "aws_key_secret": key_secret,
    }


def seconds_to_human_time(seconds):
    if seconds < 0:
        return None
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    d, h = divmod(h, 24)
    if d:
        return "{} days".format(int(d))
    if h:
        return "{} hours".format(int(h))
    if m:
        return "{} minutes".format(int(h))
    return "{} seconds".format(int(s))


@router.get("/credentials", status_code=HTTP_200_OK)
async def get_user_keys(request: Request, auth=Depends(Auth)):
    token_claims = await auth.get_token_claims()
    user_id = token_claims.get("sub")
    now = datetime.now(timezone.utc)

    def get_key_expiration(key_status, key_creation_date):
        if (
            key_status == "Inactive"
            or (now - key_creation_date).days > config["IAM_KEYS_LIFETIME_DAYS"]
        ):
            return "expired"
        expires_in = (
            key_creation_date + timedelta(days=config["IAM_KEYS_LIFETIME_DAYS"]) - now
        )
        return f"expires in {seconds_to_human_time(expires_in.total_seconds())}"

    return [
        {
            "aws_key_id": key["AccessKeyId"],
            "status": get_key_expiration(key["Status"], key["CreateDate"]),
        }
        for key in aws_utils.list_iam_user_keys(user_id)
    ]


@router.delete("/credentials/{key_id}", status_code=HTTP_204_NO_CONTENT)
async def delete_user_key(request: Request, key_id: str, auth=Depends(Auth)):
    token_claims = await auth.get_token_claims()
    user_id = token_claims.get("sub")
    aws_utils.delete_iam_user_key(user_id, key_id)
