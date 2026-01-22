from typing import Tuple, Union

import boto3
import json
import os
from botocore.exceptions import ClientError

from gen3workflow import logger
from gen3workflow.config import config


def dict_to_sorted_json_str(obj: dict) -> str:
    """
    Reads a Python dict and returns a JSON string with ordered keys
    Use case: when comparing JSON objects returned by AWS, comparisons are deterministic and less flaky
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def get_boto3_client(service_name: str, **kwargs):
    """
    Create a boto3 client for the specified AWS service,
    using credentials from the config if provided,
    otherwise using IRSA as a fallback in the credential provider chain.
    """
    if config["S3_ENDPOINTS_AWS_ACCESS_KEY_ID"]:
        return boto3.client(
            service_name,
            aws_access_key_id=config["S3_ENDPOINTS_AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=config["S3_ENDPOINTS_AWS_SECRET_ACCESS_KEY"],
            **kwargs,
        )
    else:
        return boto3.client(service_name, **kwargs)


iam_client = get_boto3_client("iam")
s3_client = get_boto3_client("s3")
kms_client = get_boto3_client("kms", region_name=config["USER_BUCKETS_REGION"])
sts_client = get_boto3_client("sts")
eks_client = get_boto3_client("eks", region_name=config["EKS_CLUSTER_REGION"])


def get_safe_name_from_hostname(
    user_id: Union[str, None], reserved_length: int = 0
) -> str:
    """
    Generate a valid and length-safe name (for IAM user, S3 bucket, or IAM role)
    derived from the configured hostname and optional user ID.
    Rules:
    - IAM user names: up to 64 characters.
    - S3 bucket / IAM role names: up to 63 characters.
    - Only alphanumeric characters and the following are allowed: +=,.@_-
        (assumes HOSTNAME and user IDs are already compliant).
    Args:
        user_id (str | None): The user's unique Gen3 ID. If None, will not be included in the safe name.
        reserved_length (int): Number of characters to reserve for prefixes/suffixes.

    Returns:
        str: safe name
    """
    escaped_hostname = config["HOSTNAME"].replace(".", "-")
    safe_name = f"gen3wf-{escaped_hostname}"
    max_chars = 63 - reserved_length
    if user_id:
        max_chars = max_chars - len(f"-{user_id}")
    if len(safe_name) > max_chars:
        safe_name = safe_name[:max_chars]
    if user_id:
        safe_name = f"{safe_name}-{user_id}"
    return safe_name


def get_worker_sa_name(user_id: str) -> str:
    """
    Generate the name of the Kubernetes service account used by worker pods for the specified user.

    Args:
        user_id (str): The user's unique Gen3 ID
    Returns:
        str: service account name
    """
    safe_name = get_safe_name_from_hostname(user_id, reserved_length=len("-worker-sa"))
    return f"{safe_name}-worker-sa"


def get_bucket_name_from_user_id(user_id: str) -> str:
    """
    Generate the S3 bucket name for the specified user.

    Args:
        user_id (str): The user's unique Gen3 ID
    Returns:
        str: S3 bucket name
    """
    # Abstracted for future flexibility — currently same as safe name.
    return get_safe_name_from_hostname(user_id)


def get_existing_kms_key_for_bucket(bucket_name: str) -> Tuple[str, str]:
    """
    Return the alias and ARN of the KMS key used for this bucket. If the key doesn't exist yet,
    only return the expected key alias.

    Args:
        bucket_name (str): name of the bucket to get the KMS key alias and ARN for
        user_id (str): The user's unique Gen3 ID

    Returns:
        Tuple (str, str): KMS key alias, and KMS key ARN if the key exists, empty string otherwise
    """
    kms_key_alias = f"alias/{bucket_name}"
    try:
        output = kms_client.describe_key(KeyId=kms_key_alias)
        return kms_key_alias, output["KeyMetadata"]["Arn"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return kms_key_alias, ""
        raise


def create_iam_role_for_bucket_access(user_id: str) -> str:
    """
    Create an IAM role that can be assumed by EC2 instances to access the specified S3 bucket and KMS keys (if enabled).
    Args:
        user_id (str): The user's unique Gen3 ID
    Returns:
        str: ARN of the created IAM role
    Raises:
        Exception: If there is an error during the creation or updating of the IAM role or policy
    """
    # set up an IAM role that can be assumed as an IRSA by EC2 instances
    role_name_suffix = "-funnel-role"
    safe_name = get_safe_name_from_hostname(
        user_id, reserved_length=len(role_name_suffix)
    )
    role_name = f"{safe_name}{role_name_suffix}"
    bucket_name = get_bucket_name_from_user_id(user_id)
    aws_account_id = sts_client.get_caller_identity().get("Account")
    oidc_token_url = eks_client.describe_cluster(name=config["EKS_CLUSTER_NAME"])[
        "cluster"
    ]["identity"]["oidc"]["issuer"].replace("https://", "")

    worker_namespace = config["WORKER_PODS_NAMESPACE"]

    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            },
            {
                "Effect": "Allow",
                "Principal": {
                    f"Federated": f"arn:aws:iam::{aws_account_id}:oidc-provider/{oidc_token_url}"
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        f"{oidc_token_url}:sub": f"system:serviceaccount:{worker_namespace}:{get_worker_sa_name(user_id)}",
                        f"{oidc_token_url}:aud": "sts.amazonaws.com",
                    }
                },
            },
        ],
    }

    try:
        worker_role = iam_client.get_role(RoleName=role_name)
        logger.info(f"IAM role '{role_name}' already exists")
        current_policy = dict_to_sorted_json_str(
            worker_role["Role"]["AssumeRolePolicyDocument"]
        )
        updated_policy = dict_to_sorted_json_str(assume_role_policy_document)

        if current_policy != updated_policy:
            logger.debug(f"Updating Assume role Policy changed for '{role_name}'.")
            iam_client.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(assume_role_policy_document),
            )
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            logger.info(f"Creating IAM role '{role_name}'")
            worker_role = iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(assume_role_policy_document),
                Tags=[
                    {
                        "Key": "Name",
                        "Value": get_safe_name_from_hostname(user_id=None),
                    }
                ],
            )
            logger.info(f"Created IAM role '{role_name}'")
        else:
            raise

    policy_name = f"{role_name}-s3-access"
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:ListBucket",
                    "s3:GetBucketLocation",
                ],
                "Resource": f"arn:aws:s3:::{bucket_name}",
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject",
                    "s3:GetObject",
                ],
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
            },
        ],
    }

    if config["KMS_ENCRYPTION_ENABLED"]:
        _, kms_key_arn = get_existing_kms_key_for_bucket(bucket_name)
        if kms_key_arn:
            logger.debug(f"Adding KMS permissions to IAM policy for role '{role_name}'")
            policy_document["Statement"].append(
                {
                    "Effect": "Allow",
                    "Action": [
                        "kms:Decrypt",
                        "kms:Encrypt",
                        "kms:GenerateDataKey*",
                    ],
                    "Resource": kms_key_arn,
                }
            )

    iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(policy_document),
    )
    logger.info(f"Updated IAM policy '{policy_name}' for role '{role_name}'")

    return worker_role["Role"]["Arn"]


def setup_kms_encryption_on_bucket(bucket_name: str) -> None:
    """
    Set up KMS encryption on the bucket.
    Args:
        bucket_name (str): name of the bucket to setup KMS encryption
    Returns:
        str: KMS Key ARN
    """
    # the only way to check if the KMS key has already been created is to use an alias
    kms_key_alias, kms_key_arn = get_existing_kms_key_for_bucket(bucket_name)
    if kms_key_arn:
        logger.debug(f"Existing KMS key '{kms_key_alias}' - '{kms_key_arn}'")
    else:
        # the KMS key doesn't exist: create it
        output = kms_client.create_key(
            Tags=[
                {
                    "TagKey": "Name",
                    "TagValue": get_safe_name_from_hostname(user_id=None),
                }
            ]
        )
        kms_key_arn = output["KeyMetadata"]["Arn"]
        logger.debug(f"Created KMS key '{kms_key_arn}'")

        kms_client.create_alias(AliasName=kms_key_alias, TargetKeyId=kms_key_arn)
        logger.debug(f"Created KMS key alias '{kms_key_alias}'")

    logger.debug(f"Setting KMS encryption on bucket '{bucket_name}'")
    s3_client.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                        "KMSMasterKeyID": kms_key_arn,
                    },
                    "BucketKeyEnabled": True,
                },
            ],
        },
    )

    logger.debug("Enforcing KMS encryption through bucket policy")
    s3_client.put_bucket_policy(
        Bucket=bucket_name,
        # using 2 statements here, because for some reason the condition below allows using a
        # different key as long as "s3:x-amz-server-side-encryption: aws:kms" is specified:
        # "StringNotEquals": {
        #     "s3:x-amz-server-side-encryption": "aws:kms",
        #     "s3:x-amz-server-side-encryption-aws-kms-key-id": "{kms_key_arn}"
        # }
        Policy=f"""{{
            "Version": "2012-10-17",
            "Statement": [
                {{
                    "Sid": "RequireKMSEncryption",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:PutObject",
                    "Resource": "arn:aws:s3:::{bucket_name}/*",
                    "Condition": {{
                        "StringNotEquals": {{
                            "s3:x-amz-server-side-encryption": "aws:kms"
                        }}
                    }}
                }},
                {{
                    "Sid": "RequireSpecificKMSKey",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:PutObject",
                    "Resource": "arn:aws:s3:::{bucket_name}/*",
                    "Condition": {{
                        "StringNotEquals": {{
                            "s3:x-amz-server-side-encryption-aws-kms-key-id": "{kms_key_arn}"
                        }}
                    }}
                }}
            ]
        }}
        """,
    )
    return kms_key_arn


def create_user_bucket(user_id: str) -> Tuple[str, str, str]:
    """
    Create an S3 bucket for the specified user and return information about the bucket.

    Args:
        user_id (str): The user's unique Gen3 ID

    Returns:
        tuple: (bucket name, prefix where the user stores objects in the bucket, bucket region, kms key ARN)
    """
    user_bucket_name = get_bucket_name_from_user_id(user_id)
    try:
        s3_client.head_bucket(Bucket=user_bucket_name)
        logger.info(f"Bucket '{user_bucket_name}' already exists for user '{user_id}'")

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code != "404":
            logger.error(
                f"Error checking existence of bucket '{user_bucket_name}' for user '{user_id}': {e}"
            )
            raise
        logger.info(
            f"Bucket does not exist. Creating S3 bucket '{user_bucket_name}' for user '{user_id}'"
        )
        if config["USER_BUCKETS_REGION"] == "us-east-1":
            # it's the default region and cannot be specified in `LocationConstraint`
            s3_client.create_bucket(Bucket=user_bucket_name)
        else:
            s3_client.create_bucket(
                Bucket=user_bucket_name,
                CreateBucketConfiguration={
                    "LocationConstraint": config["USER_BUCKETS_REGION"]
                },
            )
        logger.info(f"Created S3 bucket '{user_bucket_name}' for user '{user_id}'")

        expiration_days = config["S3_OBJECTS_EXPIRATION_DAYS"]
        logger.debug(f"Setting bucket objects expiration to {expiration_days} days")
        s3_client.put_bucket_lifecycle_configuration(
            Bucket=user_bucket_name,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": f"ExpireAllAfter{expiration_days}Days",
                        "Expiration": {"Days": expiration_days},
                        "Status": "Enabled",
                        # apply to all objects:
                        "Filter": {"Prefix": ""},
                    },
                ],
            },
            # Explicitly set the algorithm to SHA-256. The default algorithm used by S3 is MD5, which is
            # not allowed by FIPS. When FIPS mode is enabled, not specifying the algorithm causes this
            # error: `Missing required header for this request: Content-MD5`.
            ChecksumAlgorithm="SHA256",
        )
    kms_key_arn = None
    if config["KMS_ENCRYPTION_ENABLED"]:
        kms_key_arn = setup_kms_encryption_on_bucket(user_bucket_name)
    else:
        logger.warning(f"Disabling KMS encryption on bucket '{user_bucket_name}'")
        s3_client.delete_bucket_encryption(Bucket=user_bucket_name)
        s3_client.delete_bucket_policy(Bucket=user_bucket_name)

    return user_bucket_name, "ga4gh-tes", config["USER_BUCKETS_REGION"], kms_key_arn


def get_all_bucket_objects(user_bucket_name: str) -> list:
    """
    Get all objects from the specified S3 bucket.
    """
    response = s3_client.list_objects_v2(Bucket=user_bucket_name)
    object_list = response.get("Contents", [])

    # list_objects_v2 can utmost return 1000 objects in a single response
    # if there are more objects, the response will have a key "IsTruncated" set to True
    # and a key "NextContinuationToken" which can be used to get the next set of objects

    # TODO:
    # Currently, all objects are loaded into memory, which can be problematic for large buckets.
    # To optimize, convert this function into a generator that accepts a `batch_size` parameter
    # (capped at 1,000) and yields objects in batches.
    # This is fine for now because this code is only called during integration tests, with a small
    # number of files in the bucket.
    while response.get("IsTruncated"):
        response = s3_client.list_objects_v2(
            Bucket=user_bucket_name,
            ContinuationToken=response.get("NextContinuationToken"),
        )
        object_list += response.get("Contents", [])

    return object_list


def delete_all_bucket_objects(user_id: str, user_bucket_name: str) -> None:
    """
    Deletes all objects from the specified S3 bucket.

    Args:
        user_id (str): The user's unique Gen3 ID.
        user_bucket_name (str): The name of the S3 bucket.
    """
    object_list = get_all_bucket_objects(user_bucket_name)

    if not object_list:
        return

    logger.debug(
        f"Deleting all contents from '{user_bucket_name}' for user '{user_id}' before deleting the bucket"
    )
    keys = [{"Key": obj.get("Key")} for obj in object_list]

    # According to the docs, up to 1000 objects can be deleted in a single request:
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#S3.Client.delete_objects

    # TODO: When `get_all_bucket_objects` is converted to a generator,
    # we can remove this batching logic and retrieve objects in batches of 1,000 for deletion.
    limit = 1000
    for offset in range(0, len(keys), limit):
        response = s3_client.delete_objects(
            Bucket=user_bucket_name,
            Delete={"Objects": keys[offset : offset + limit]},
        )
        if response.get("Errors"):
            logger.error(
                f"Failed to delete objects from bucket '{user_bucket_name}' for user '{user_id}': {response}"
            )
            raise Exception(response)


def delete_user_bucket(user_id: str) -> Union[str, None]:
    """
    Deletes all objects from a user's S3 bucket before deleting the bucket itself.

    Args:
        user_id (str): The user's unique Gen3 ID

    Raises:
        Exception: If there is an error during the deletion process.
    """
    user_bucket_name = get_bucket_name_from_user_id(user_id)

    try:
        s3_client.head_bucket(Bucket=user_bucket_name)
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "404":
            logger.warning(
                f"Bucket '{user_bucket_name}' not found for user '{user_id}'."
            )
            return None

    logger.info(f"Deleting bucket '{user_bucket_name}' for user '{user_id}'")
    try:
        delete_all_bucket_objects(user_id, user_bucket_name)
        s3_client.delete_bucket(Bucket=user_bucket_name)
        return user_bucket_name

    except Exception as e:
        logger.error(
            f"Failed to delete bucket '{user_bucket_name}' for user '{user_id}': {e}"
        )
        raise
