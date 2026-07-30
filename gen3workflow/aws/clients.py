import boto3
from gen3workflow.config import config


def get_boto3_client(service_name: str, **kwargs):
    """
    Create a boto3 client for the specified AWS service,
    using credentials from the config if provided,
    otherwise using IRSA as a fallback in the credential provider chain.
    """
    if service_name == "s3":
        if config["S3_UPSTREAM_ENDPOINT"]:
            kwargs["endpoint_url"] = config["S3_UPSTREAM_ENDPOINT"]
        if config["S3_ENDPOINTS_AWS_ACCESS_KEY_ID"]:
            kwargs["aws_access_key_id"] = config["S3_ENDPOINTS_AWS_ACCESS_KEY_ID"]
            kwargs["aws_secret_access_key"] = config[
                "S3_ENDPOINTS_AWS_SECRET_ACCESS_KEY"
            ]
    return boto3.client(service_name, **kwargs)


iam_client = get_boto3_client("iam")
s3_client = get_boto3_client("s3", region_name=config["USER_BUCKETS_REGION"])
kms_client = get_boto3_client("kms", region_name=config["USER_BUCKETS_REGION"])
sts_client = get_boto3_client("sts")
eks_client = get_boto3_client("eks", region_name=config["EKS_CLUSTER_REGION"])
s3files_client = get_boto3_client("s3files", region_name=config["USER_BUCKETS_REGION"])
ec2_client = get_boto3_client("ec2", region_name=config["USER_BUCKETS_REGION"])
