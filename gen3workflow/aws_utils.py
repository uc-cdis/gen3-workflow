import json
from typing import List, Tuple

import boto3
from botocore.exceptions import ClientError
from fastapi import HTTPException
from starlette.status import HTTP_404_NOT_FOUND

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
    user_bucket_name = get_safe_name_from_user_id(user_id)
    s3_client = boto3.client("s3")
    s3_client.create_bucket(Bucket=user_bucket_name)
    return user_bucket_name, "ga4gh-tes", config["USER_BUCKETS_REGION"]


def create_or_update_policy(
    policy_name: str, policy_document: dict, path_prefix: str, tags: List[dict]
) -> str:
    """
    Update the specified policy with the specified document and tags, or create it if it doesn't
    exist.

    Args:
        policy_name (str): name of the IAM policy to create or update
        policy_document (dict): policy document
        path_prefix (str): policy path prefix
        tags (list(dict)): IAM tags to set on the policy

    Returns:
        str: policy ARN
    """
    # attempt to create the policy
    try:
        response = iam_client.create_policy(
            PolicyName=policy_name,
            Path=path_prefix,
            PolicyDocument=json.dumps(policy_document),
            Tags=tags,
        )
        assert "Arn" in response.get("Policy", {}), f"{iam_resp_err}: {response}"
        return response["Policy"]["Arn"]
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityAlreadyExists":
            raise

        # policy already exists: update it.
        # find the right policy
        response = iam_client.list_policies(PathPrefix=path_prefix)
        assert "Policies" in response, f"{iam_resp_err}: {response}"
        for policy in response["Policies"]:
            assert "PolicyName" in policy, f"{iam_resp_err}: {policy}"
            assert "Arn" in policy, f"{iam_resp_err}: {policy}"
            if policy["PolicyName"] == policy_name:
                break

        # there can only be up to 5 versions, so delete old versions of this policy
        response = iam_client.list_policy_versions(PolicyArn=policy["Arn"])
        assert "Versions" in response, f"{iam_resp_err}: {response}"
        for version in response["Versions"]:
            assert "VersionId" in version, f"{iam_resp_err}: {version}"
            assert "IsDefaultVersion" in version, f"{iam_resp_err}: {version}"
            if version["IsDefaultVersion"]:
                continue  # do not delete the latest versions
            iam_client.delete_policy_version(
                PolicyArn=policy["Arn"], VersionId=version["VersionId"]
            )

        # update the policy by creating a new version
        iam_client.create_policy_version(
            PolicyArn=policy["Arn"],
            PolicyDocument=json.dumps(policy_document),
            SetAsDefault=True,
        )
        return policy["Arn"]


def create_iam_user_and_key(user_id: str, system_key: bool) -> Tuple[str, str]:
    """
    Create an IAM user and an IAM key with access to a freshly created bucket associated with
    this user.

    Args:
        user_id (str): The user's unique Gen3 ID
        system_key (bool): Whether the generated key is meant to be used by the server (if True)
            or by the end user (if False). If True, append "-bot" to the IAM user name.

    Returns:
        tuple(str, str): IAM key ID and secret
    """
    if system_key:
        iam_user_name = get_safe_name_from_user_id(f"{user_id}-bot")
    else:
        iam_user_name = get_safe_name_from_user_id(user_id)
    escaped_hostname = config["HOSTNAME"].replace(".", "-")
    iam_tags = [
        {
            "Key": "name",
            "Value": f"gen3wf-{escaped_hostname}",
        },
    ]

    try:
        iam_client.create_user(UserName=iam_user_name, Tags=iam_tags)
    except ClientError as e:
        # if the user already exists, ignore the error and proceed
        if e.response["Error"]["Code"] != "EntityAlreadyExists":
            raise

    # grant the IAM user access to the user's s3 bucket
    bucket_name, bucket_prefix, _ = create_user_bucket(user_id)
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowListingBucketFolder",
                "Effect": "Allow",
                "Action": ["s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket_name}"],
                "Condition": {"StringLike": {"s3:prefix": [f"{bucket_prefix}/*"]}},
            },
            {
                "Sid": "AllowManagingBucketFolder",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                "Resource": [f"arn:aws:s3:::{bucket_name}/{bucket_prefix}/*"],
            },
        ],
    }
    path_prefix = f"/{iam_user_name}/"  # used later to get existing policies' ARN
    policy_arn = create_or_update_policy(
        f"{iam_user_name}-policy", policy_document, path_prefix, iam_tags
    )
    iam_client.attach_user_policy(PolicyArn=policy_arn, UserName=iam_user_name)

    # create a key for this user
    key = iam_client.create_access_key(UserName=iam_user_name)
    assert "AccessKeyId" in key.get("AccessKey", {}), f"{iam_resp_err}: {key}"
    assert "SecretAccessKey" in key.get("AccessKey", {}), f"{iam_resp_err}: {key}"

    return key["AccessKey"]["AccessKeyId"], key["AccessKey"]["SecretAccessKey"]


def list_iam_user_keys(user_id: str) -> List[dict]:
    """
    List the IAM keys associated with the specified user.

    Args:
        user_id (str): The user's unique Gen3 ID

    Returns:
        list[dict]: the user's keys
    """
    iam_user_name = get_safe_name_from_user_id(user_id)
    try:
        response = iam_client.list_access_keys(UserName=iam_user_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return []  # user does not exist in IAM, so they have no IAM keys
        else:
            raise
    assert "AccessKeyMetadata" in response, f"{iam_resp_err}: {response}"
    for key in response["AccessKeyMetadata"]:
        assert "AccessKeyId" in key, f"{iam_resp_err}: {key}"
        assert "CreateDate" in key, f"{iam_resp_err}: {key}"
        assert "Status" in key, f"{iam_resp_err}: {key}"
    return response["AccessKeyMetadata"]


def delete_iam_user_key(user_id: str, key_id: str) -> None:
    """
    Delete an IAM key from AWS.

    Args:
        user_id (str): The user's unique Gen3 ID
        key_id (str): ID of the IAM key to delete
    """
    try:
        iam_client.delete_access_key(
            UserName=get_safe_name_from_user_id(user_id),
            AccessKeyId=key_id,
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            raise HTTPException(
                HTTP_404_NOT_FOUND,
                f"No such key: '{key_id}'",
            )
