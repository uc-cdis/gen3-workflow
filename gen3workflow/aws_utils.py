from typing import Tuple, Union

import boto3
from botocore.exceptions import ClientError

from gen3workflow import logger
from gen3workflow.config import config


iam_client = boto3.client("iam")
kms_client = boto3.client("kms", region_name=config["USER_BUCKETS_REGION"])
s3_client = boto3.client("s3")


def get_safe_name_from_hostname(user_id: Union[str, None]) -> str:
    """
    Generate a valid IAM user name or S3 bucket name for the specified user.
    - IAM user names can contain up to 64 characters. They can only contain alphanumeric characters
    and/or the following: +=,.@_- (not enforced here since user IDs and hostname should not contain
    special characters).
    - S3 bucket names can contain up to 63 characters.

    Args:
        user_id (str): The user's unique Gen3 ID. If None, will not be included in the safe name.

    Returns:
        str: safe name
    """
    escaped_hostname = config["HOSTNAME"].replace(".", "-")
    safe_name = f"gen3wf-{escaped_hostname}"
    max_chars = 63
    if user_id:
        max_chars = max_chars - len(f"-{user_id}")
    if len(safe_name) > max_chars:
        safe_name = safe_name[:max_chars]
    if user_id:
        safe_name = f"{safe_name}-{user_id}"
    return safe_name


def get_existing_kms_key_for_bucket(bucket_name):
    """
    Return the alias and ARN of the KMS key used for this bucket. If the key doesn't exist yet,
    only return the expected key alias.

    Args:
        bucket_name (str): name of the bucket to get the KMS key alias and ARN for

    Returns:
        Tuple (str, str or None): KMS key alias, and KMS key ARN if the key exists, None otherwise
    """
    kms_key_alias = f"alias/key-{bucket_name}"
    try:
        output = kms_client.describe_key(KeyId=kms_key_alias)
        return kms_key_alias, output["KeyMetadata"]["Arn"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return kms_key_alias, None
        raise


def create_user_bucket(user_id: str) -> Tuple[str, str, str]:
    """
    Create an S3 bucket for the specified user and return information about the bucket.

    Args:
        user_id (str): The user's unique Gen3 ID

    Returns:
        tuple: (bucket name, prefix where the user stores objects in the bucket, bucket region)
    """
    user_bucket_name = get_safe_name_from_hostname(user_id)
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

    # set up KMS encryption on the bucket.
    # the only way to check if the KMS key has already been created is to use an alias
    kms_key_alias, kms_key_arn = get_existing_kms_key_for_bucket(user_bucket_name, user_id)
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

    # TODO enable KMS encryption when Funnel workers can push with KMS key or use our S3 endpoint
    # logger.debug(f"Setting KMS encryption on bucket '{user_bucket_name}'")
    # s3_client.put_bucket_encryption(
    #     Bucket=user_bucket_name,
    #     ServerSideEncryptionConfiguration={
    #         "Rules": [
    #             {
    #                 "ApplyServerSideEncryptionByDefault": {
    #                     "SSEAlgorithm": "aws:kms",
    #                     "KMSMasterKeyID": kms_key_arn,
    #                 },
    #                 "BucketKeyEnabled": True,
    #             },
    #         ],
    #     },
    # )

    # logger.debug("Enforcing KMS encryption through bucket policy")
    # s3_client.put_bucket_policy(
    #     Bucket=user_bucket_name,
    #     Policy=f"""{{
    #         "Version": "2012-10-17",
    #         "Statement": [
    #             {{
    #                 "Sid": "RequireKMSEncryption",
    #                 "Effect": "Deny",
    #                 "Principal": "*",
    #                 "Action": "s3:PutObject",
    #                 "Resource": "arn:aws:s3:::{user_bucket_name}/*",
    #                 "Condition": {{
    #                     "StringNotLikeIfExists": {{
    #                         "s3:x-amz-server-side-encryption-aws-kms-key-id": "{kms_key_arn}"
    #                     }}
    #                 }}
    #             }}
    #         ]
    #     }}
    #     """,
    # )

    expiration_days = config["S3_OBJECTS_EXPIRATION_DAYS"]
    logger.debug(f"Setting bucket objects expiration to {expiration_days} days")
    s3_client.put_bucket_lifecycle_configuration(
        Bucket=user_bucket_name,
        LifecycleConfiguration={
            "Rules": [
                {
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

    return user_bucket_name, "ga4gh-tes", config["USER_BUCKETS_REGION"]
