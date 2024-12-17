from typing import Tuple

import boto3

from gen3workflow.config import config


iam_client = boto3.client("iam")
iam_resp_err = "Unexpected response from AWS IAM"


def get_safe_name_from_user_id(user_id: str) -> str:
    """
    Generate a valid IAM user name or S3 bucket name for the specified user.
    - IAM user names can contain up to 64 characters. They can only contain alphanumeric characters
    and/or the following: +=,.@_- (not enforced here since user IDs and hostname should not contain
    special characters).
    - S3 bucket names can contain up to 63 characters.

    Args:
        user_id (str): The user's unique Gen3 ID

    Returns:
        str: safe name
    """
    escaped_hostname = config["HOSTNAME"].replace(".", "-")
    safe_name = f"gen3wf-{escaped_hostname}"
    max = 63 - len(f"-{user_id}")
    if len(safe_name) > max:
        safe_name = safe_name[:max]
    safe_name = f"{safe_name}-{user_id}"
    return safe_name


def create_user_bucket(user_id: str) -> Tuple[str, str, str]:
    """
    Create an S3 bucket for the specified user and return information about the bucket.

    Args:
        user_id (str): The user's unique Gen3 ID

    Returns:
        tuple: (bucket name, prefix where the user stores objects in the bucket, bucket region)
    """
    # TODO lifetime policy and encryption
    user_bucket_name = get_safe_name_from_user_id(user_id)
    s3_client = boto3.client("s3")
    s3_client.create_bucket(Bucket=user_bucket_name)
    return user_bucket_name, "ga4gh-tes", config["USER_BUCKETS_REGION"]
