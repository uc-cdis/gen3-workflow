import json
import random
from cachelib import SimpleCache
from typing import Tuple, Union

import asyncio
from botocore.exceptions import ClientError
from fastapi import HTTPException
from starlette.status import HTTP_400_BAD_REQUEST
from cachelib import SimpleCache

from gen3workflow import logger
from gen3workflow.aws.aws_utils import (
    dict_to_sorted_json_str,
    get_bucket_name_from_user_id,
    get_safe_name_from_hostname,
    get_worker_sa_name,
)
from gen3workflow.config import config

from gen3workflow.aws import clients

USER_BUCKET_CACHE = SimpleCache(default_timeout=config["USER_BUCKET_CACHE_SECONDS"])

# Arbitrarily set expiration of older versions of bucket objects,
# required when bucket versioning is enabled.
NONCURRENT_VERSION_EXPIRATION_DAYS = 3


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
        output = clients.kms_client.describe_key(KeyId=kms_key_alias)
        return kms_key_alias, output["KeyMetadata"]["Arn"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return kms_key_alias, ""
        raise


def create_iam_role_for_funnel_bucket_access(user_id: str) -> str:
    """
    Create an IAM role that can be assumed by EC2 instances to access the specified S3 bucket and KMS keys (if enabled).
    TODO do not update if not needed

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
    aws_account_id = clients.sts_client.get_caller_identity().get("Account")
    oidc_token_url = clients.eks_client.describe_cluster(
        name=config["EKS_CLUSTER_NAME"]
    )["cluster"]["identity"]["oidc"]["issuer"].replace("https://", "")

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
                        f"{oidc_token_url}:sub": f"system:serviceaccount:{config["WORKER_PODS_NAMESPACE"]}:{get_worker_sa_name(user_id)}",
                        f"{oidc_token_url}:aud": "sts.amazonaws.com",
                    }
                },
            },
        ],
    }

    try:
        worker_role = clients.iam_client.get_role(RoleName=role_name)
        logger.info(f"IAM role '{role_name}' already exists")
        current_policy = dict_to_sorted_json_str(
            worker_role["Role"]["AssumeRolePolicyDocument"]
        )
        updated_policy = dict_to_sorted_json_str(assume_role_policy_document)

        if current_policy != updated_policy:
            logger.debug(f"Updating Assume role Policy changed for '{role_name}'.")
            clients.iam_client.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(assume_role_policy_document),
            )
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise
        logger.info(f"Creating IAM role '{role_name}'")
        worker_role = clients.iam_client.create_role(
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
                    "s3:DeleteObject",
                ],
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
            },
        ],
    }

    if config["KMS_ENCRYPTION_ENABLED"]:
        _, kms_key_arn = get_existing_kms_key_for_bucket(bucket_name)
        if not kms_key_arn:
            err_msg = "Bucket misconfigured. Hit the `GET /storage/setup` endpoint and try again."
            logger.error(
                f"No existing KMS key found for bucket '{bucket_name}'. {err_msg}"
            )
            raise HTTPException(HTTP_400_BAD_REQUEST, err_msg)
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

    clients.iam_client.put_role_policy(
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
        output = clients.kms_client.create_key(
            Tags=[
                {
                    "TagKey": "Name",
                    "TagValue": get_safe_name_from_hostname(user_id=None),
                }
            ]
        )
        kms_key_arn = output["KeyMetadata"]["Arn"]
        logger.debug(f"Created KMS key '{kms_key_arn}'")

        clients.kms_client.create_alias(
            AliasName=kms_key_alias, TargetKeyId=kms_key_arn
        )
        logger.debug(f"Created KMS key alias '{kms_key_alias}'")

    logger.debug(f"Setting KMS encryption on bucket '{bucket_name}'")
    try:
        existing_bucket_encryption = clients.s3_client.get_bucket_encryption(
            Bucket=bucket_name
        )["ServerSideEncryptionConfiguration"]
        if len(existing_bucket_encryption["Rules"]) > 0:
            # remove this default to allow comparing with the new rules
            existing_bucket_encryption["Rules"][0].pop("BlockedEncryptionTypes")
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code != "ServerSideEncryptionConfigurationNotFoundError":
            raise
        existing_bucket_encryption = None
    new_bucket_encryption = {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": kms_key_arn,
                },
                "BucketKeyEnabled": True,
            },
        ],
    }
    if new_bucket_encryption != existing_bucket_encryption:
        clients.s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration=new_bucket_encryption,
        )
    else:
        logger.debug("Bucket encryption is already up to date")

    logger.debug("Enforcing KMS encryption through bucket policy")
    try:
        existing_bucket_policy = json.loads(
            clients.s3_client.get_bucket_policy(Bucket=bucket_name)["Policy"]
        )
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code != "NoSuchBucketPolicy":
            raise
        existing_bucket_policy = None
    # The deny in this policy fires when the headers are present but wrong (e.g. trying not to use
    # KMS encryption, or trying to use a different KMS key). If the headers are absent, the request
    # is accepted and AWS falls back on the bucket's default encryption (set above).
    # TODO: stop specifying the KMS key in the funnel config
    new_bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "RequireKMSEncryption",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
                "Condition": {
                    "StringNotEqualsIfExists": {
                        "s3:x-amz-server-side-encryption": "aws:kms"
                    },
                    "Null": {"s3:x-amz-server-side-encryption": "false"},
                },
            },
            {
                "Sid": "RequireSpecificKMSKey",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
                "Condition": {
                    "StringNotEqualsIfExists": {
                        "s3:x-amz-server-side-encryption-aws-kms-key-id": [
                            kms_key_arn,
                            kms_key_alias,
                        ]
                    },
                    "Null": {"s3:x-amz-server-side-encryption-aws-kms-key-id": "false"},
                },
            },
        ],
    }
    if new_bucket_policy != existing_bucket_policy:
        clients.s3_client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(new_bucket_policy),
        )
    else:
        logger.debug("Bucket policy is already up to date")

    return kms_key_arn


def enable_bucket_versioning(bucket_name: str) -> None:
    """
    Enable versioning on the specified S3 bucket.

    Args:
        bucket_name (str): name of the bucket to enable versioning on
    """
    try:
        existing_versioning = clients.s3_client.get_bucket_versioning(
            Bucket=bucket_name
        )
        if existing_versioning.get("Status") != "Enabled":
            clients.s3_client.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration={"Status": "Enabled"},
            )
            logger.debug(f"Enabled versioning on bucket '{bucket_name}'")
        else:
            logger.debug(f"Bucket '{bucket_name}' already has versioning enabled")
    except ClientError as e:
        logger.error(
            f"Failed to enable versioning on bucket '{bucket_name}': {e.response['Error']['Message']}"
        )
        raise


async def _create_user_bucket(user_id: str) -> Tuple[str, str]:
    """
    Create an S3 bucket for the specified user and return information about the bucket.

    Args:
        user_id (str): The user's unique Gen3 ID

    Returns:
        tuple: (bucket name, kms key ARN)
    """
    user_bucket_name = get_bucket_name_from_user_id(user_id)
    try:
        clients.s3_client.head_bucket(Bucket=user_bucket_name)
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
        try:
            if config["USER_BUCKETS_REGION"] == "us-east-1":
                # it's the default region and cannot be specified in `LocationConstraint`
                clients.s3_client.create_bucket(Bucket=user_bucket_name)
            else:
                clients.s3_client.create_bucket(
                    Bucket=user_bucket_name,
                    CreateBucketConfiguration={
                        "LocationConstraint": config["USER_BUCKETS_REGION"]
                    },
                )
        except clients.s3_client.exceptions.BucketAlreadyOwnedByYou:
            # `An error occurred (BucketAlreadyOwnedByYou) when calling the CreateBucket operation:
            # Your previous request to create the named bucket succeeded and you already own it.`
            # This can happen if this function is called multiple times in a row.
            logger.info(
                f"S3 bucket '{user_bucket_name}' already exists (race condition?): proceeding"
            )
        else:
            waiter = clients.s3_client.get_waiter("bucket_exists")
            waiter.wait(Bucket=user_bucket_name)
            logger.info(f"Created S3 bucket '{user_bucket_name}' for user '{user_id}'")

    expiration_days = config["S3_OBJECTS_EXPIRATION_DAYS"]

    logger.debug(f"Setting bucket objects expiration to {expiration_days} days")
    clients.s3_client.put_bucket_lifecycle_configuration(
        Bucket=user_bucket_name,
        LifecycleConfiguration={
            "Rules": [
                {
                    "ID": f"ExpireAllAfter{expiration_days}Days",
                    "Expiration": {"Days": expiration_days},
                    "NoncurrentVersionExpiration": {
                        "NoncurrentDays": NONCURRENT_VERSION_EXPIRATION_DAYS
                    },
                    "Status": "Enabled",
                    # apply to all objects:
                    "Filter": {"Prefix": ""},
                },
            ],
        },
        # Explicitly set the algorithm to SHA-256. The default algorithm used by S3 is MD5,
        # which is not allowed by FIPS. When FIPS mode is enabled, not specifying the algorithm
        # causes this error: `Missing required header for this request: Content-MD5`.
        ChecksumAlgorithm="SHA256",
    )

    kms_key_arn = None
    if config["KMS_ENCRYPTION_ENABLED"]:
        kms_key_arn = setup_kms_encryption_on_bucket(user_bucket_name)
    else:
        logger.warning(f"Disabling KMS encryption on bucket '{user_bucket_name}'")
        clients.s3_client.delete_bucket_encryption(Bucket=user_bucket_name)
        clients.s3_client.delete_bucket_policy(Bucket=user_bucket_name)

    if config["ENABLE_S3_FILES"]:
        # Bucket versioning is necessary for S3Files
        enable_bucket_versioning(user_bucket_name)

    return user_bucket_name, kms_key_arn


async def create_user_bucket(user_id: str) -> Tuple[str, str, str]:
    """
    Wrapper for `_create_user_bucket` that handles caching and retries.

    Gracefully handles race conditions, for example:
    `An error occurred (OperationAborted) when calling the PutBucketEncryption operation:
    A conflicting conditional operation is currently in progress against this resource.`
    """
    if USER_BUCKET_CACHE.has(user_id):
        return USER_BUCKET_CACHE.get(user_id)

    max_tries = 3
    retry_delay = 1
    retry_backoff_factor = 2
    for attempt in range(1, max_tries + 1):
        try:
            bucket_info = await _create_user_bucket(user_id)
            USER_BUCKET_CACHE.set(user_id, bucket_info)
            return bucket_info
        except ClientError as e:
            if (
                e.response["Error"]["Code"] != "OperationAborted"
                or attempt == max_tries
            ):
                raise
            # retry with exponential backoff
            delay = retry_delay * (retry_backoff_factor**attempt)
            delay += delay * 0.1 * random.uniform(-1, 1)  # add jitter
            logger.warning(
                f"Exception during bucket creation: {e}. Retrying in {delay:.2f} seconds"
            )
            await asyncio.sleep(delay)


def _delete_all_bucket_objects(user_id: str, user_bucket_name: str) -> None:
    """
    Deletes all objects from the specified S3 bucket.

    Args:
        user_id (str): The user's unique Gen3 ID.
        user_bucket_name (str): The name of the S3 bucket.
    """
    logger.debug(
        f"Deleting all contents from '{user_bucket_name}' for user '{user_id}' before deleting the bucket"
    )
    bucket = clients.s3_resource.Bucket(user_bucket_name)

    # Cancel incomplete multipart uploads to avoid storage charges for orphaned parts
    for upload in bucket.multipart_uploads.all():
        upload.abort()

    for response in bucket.object_versions.delete():
        # boto returns one response for each underlying batch
        if response.get("Errors"):
            raise Exception(
                f"Unable to delete bucket object versions: {response['Errors']}"
            )

    for response in bucket.objects.delete():
        if response.get("Errors"):
            raise Exception(
                f"Unable to delete bucket object versions: {response['Errors']}"
            )


def cleanup_user_bucket(user_id: str, delete_bucket: bool) -> Union[str, None]:
    """
    Empty a user's S3 bucket and optionally delete the bucket.

    Args:
        user_id: User identifier used to derive the bucket name.
        delete_bucket:  If True, delete the bucket after removing all objects.

    Returns:
        Bucket name if it exists and cleanup was performed, otherwise None
        if the bucket does not exist.

    Raises:
        Exception: Propagates unexpected errors during cleanup or deletion.
    """
    user_bucket_name = get_bucket_name_from_user_id(user_id)

    try:
        clients.s3_client.head_bucket(Bucket=user_bucket_name)
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "404":
            logger.warning(
                f"Bucket '{user_bucket_name}' not found for user '{user_id}'."
            )
            return None
    try:
        _delete_all_bucket_objects(user_id, user_bucket_name)
        if delete_bucket:
            logger.info(
                f"Initializing delete for bucket '{user_bucket_name}' for user '{user_id}'"
            )
            clients.s3_client.delete_bucket(Bucket=user_bucket_name)
        return user_bucket_name

    except Exception as e:
        logger.error(
            f"Failed to cleanup bucket '{user_bucket_name}' for user '{user_id}': {e}"
        )
        raise
