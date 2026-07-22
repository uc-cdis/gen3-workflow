from botocore.exceptions import ClientError
import time

from gen3workflow import logger
from gen3workflow.config import config
from gen3workflow.aws.clients import s3files_client, eks_client, ec2_client

# NFS port used for all communication between EKS pods and S3 Files mount targets.
NFS_PORT = 2049

# --------------------------------------------------------------------------- #
# File system management
# --------------------------------------------------------------------------- #


def get_s3_files_system(bucket_name: str) -> str | None:
    """
    Look up an existing S3 Files file system for the given bucket.

    Args:
        bucket_name: name of the source S3 bucket.

    Returns:
        The file system ID (if exists).
    """
    bucket_arn = f"arn:aws:s3:::{bucket_name}"
    logger.debug(
        f"Checking for an existing S3 Files file system for bucket '{bucket_name}'..."
    )

    try:
        paginator = s3files_client.get_paginator("list_file_systems")
        for page in paginator.paginate():
            for fs in page.get("FileSystems", []):
                if fs.get("Bucket") == bucket_arn:
                    fs_id = fs["FileSystemId"]
                    logger.debug(
                        f"Found existing S3 Files file system '{fs_id}' (state: {fs['LifeCycleState']})"
                    )
                    return fs_id
    except ClientError as e:
        logger.error(
            f"Failed to list S3 Files file systems: {e.response['Error']['Message']}"
        )
        raise

    return None


def get_filesystem_status(file_system_id: str) -> tuple[str | None, str | None]:
    """
    Fetch the status of an S3 Files file system.

    Args:
        file_system_id: The ID of the file system to check.

    Returns:
        A tuple of (status, status_message):
        - (status, status_message) on success, e.g. ("AVAILABLE", None)
        - (None, error_message) if the file system doesn't exist or the
          lookup fails.
    """
    if not file_system_id:
        return None, "file_system_id must not be empty"

    try:
        fs = s3files_client.get_file_system(fileSystemId=file_system_id)
    except s3files_client.exceptions.ResourceNotFoundException:
        return None, f"File system with file_system_id={file_system_id} does not exist"
    except ClientError as e:
        return None, f"Failed to fetch file system {file_system_id}: {e}"

    if not fs:
        return None, f"File system with file_system_id={file_system_id} does not exist"

    return fs.get("status"), fs.get("statusMessage")


def get_mount_target_status(file_system_id: str):
    # TODO: list mount targets and get their statuses, and unify into a single
    # usable status (e.g. "ready" only once all expected mount targets
    # are in an available state).

    # TODO: What if new AZs are added to the node after initial bucket setup? Filesystem may need new mount targets in these AZs too.
    # This should not be the responsibility of this function, but where to put it?

    return "Not ready"


def _create_s3_files_system(bucket_name: str, role_arn: str) -> str:
    """
    Creating S3 Files file system for the given bucket.

    Args:
        bucket_name: name of the source S3 bucket.
        role_arn: ARN of the IAM role S3 Files assumes to sync with the bucket.

    Returns:
        The file system ID.
    """
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    try:
        response = s3files_client.create_file_system(
            bucket=bucket_arn,
            prefix="funnel-temp-files/",
            roleArn=role_arn,
            tags=[{"key": "app-name", "value": "gen3-workflow"}],
        )
        file_system_id = response["fileSystemId"]
        logger.debug(
            f"Created new S3 Files file system '{file_system_id}' for bucket '{bucket_name}'"
        )
        return file_system_id
    except ClientError as e:
        logger.error(
            f"Failed to create S3 Files file system for bucket '{bucket_name}': {e.response['Error']['Message']}"
        )
        raise


# --------------------------------------------------------------------------- #
# Mount target management
# --------------------------------------------------------------------------- #


def create_mount_target_for_file_system(
    file_system_id: str, subnet_id: str, mount_target_sg_id: str
) -> None:
    """
    Create a mount target for the given file system in the given subnet.

    Args:
        file_system_id: the S3 Files file system to attach the mount target to.
        subnet_id: subnet where the mount target's ENI will be created in.
        mount_target_sg_id: security group to attach to the mount target's ENI.
    """
    try:
        response = s3files_client.create_mount_target(
            fileSystemId=file_system_id,
            subnetId=subnet_id,
            securityGroups=[mount_target_sg_id],
        )
        logger.info(
            "Created mount target %s in subnet %s (status=%s)",
            response.get("mountTargetId"),
            subnet_id,
            response.get("status"),
        )
    except ClientError as exc:
        logger.error("Failed to create mount target in subnet %s: %s", subnet_id, exc)
        raise


def list_mount_targets_for_file_system(file_system_id: str) -> list[dict]:
    """
    List all mount targets currently provisioned for a file system.

    Returns:
        A flat list of mount target dicts
        [{
            'mountTargetId': 'string',
            'availabilityZoneId': 'string',
            'fileSystemId': 'string',
            'status': 'available'|'creating'|'deleting'|'deleted'|'error'|'updating',
            'statusMessage': 'string',
            'ipv4Address': 'string',
            'ipv6Address': 'string',
            'networkInterfaceId': 'string',
            'ownerId': 'string',
            'subnetId': 'string',
            'vpcId': 'string'
        },..]
    }
    """
    mount_targets = []
    try:
        paginator = s3files_client.get_paginator("list_mount_targets")
        for page in paginator.paginate(fileSystemId=file_system_id):
            mount_targets.extend(page.get("mountTargets", []))
    except ClientError as e:
        logger.error(
            f"Failed to list mount targets for {file_system_id=}: {e.response['Error']['Message']}"
        )
        raise
    return mount_targets


# --------------------------------------------------------------------------- #
# Networking / security groups
# --------------------------------------------------------------------------- #


def _get_vpc_id() -> str:
    """
    Return the VPC ID the EKS cluster's nodes run in. Used to determine which VPC
    the S3 Files mount targets should be created in.
    """
    cluster = eks_client.describe_cluster(name=config["EKS_CLUSTER_NAME"])
    return cluster["cluster"]["resourcesVpcConfig"]["vpcId"]


def _get_available_az_to_subnet(discovery_tag: str) -> dict[str, str]:
    """
    Get one subnet ID per AZ where EKS pods can be scheduled, so that one S3 Files
    mount target can be created per AZ.
    """
    subnets = ec2_client.describe_subnets(
        Filters=[{"Name": "tag:karpenter.sh/discovery", "Values": [discovery_tag]}],
    )["Subnets"]
    return {subnet["AvailabilityZoneId"]: subnet["SubnetId"] for subnet in subnets}


def _get_eks_security_groups() -> tuple[str, str]:
    """
    Return (sg_id, sg_name) for the EKS security group that Karpenter attaches
    to an EKS worker node in this cluster.
    """
    # TODO: Determine if these need to be configurable.
    eks_sg_names = [
        f"{config["EKS_CLUSTER_NAME"]}_EKS_workers_sg",
        f"{config["EKS_CLUSTER_NAME"]}_EKS_nodepool_jupyter_sg",
    ]
    security_groups = ec2_client.describe_security_groups(
        Filters=[{"Name": "group-name", "Values": eks_sg_names}]
    )["SecurityGroups"]
    return [(group["GroupId"], group["GroupName"]) for group in security_groups]


# TODO: Investigate if this can be moved to server startup logic or elsewhere?
# Since the `create` part is only needed once per cluster, no need to run for every bucket.
# This takes approximately 2 seconds to run everytime it is invoked.
def _get_or_create_security_groups(vpc_id: str) -> str:
    """
    Ensure the mount target security group exists and has the correct bidirectional
    NFS rules in place against every EKS worker security group:

    | Security group | Rule type | Protocol | Port | Source/destination           |
    |-----------------|-----------|----------|------|-------------------------------|
    | Compute SG      | Outbound  | TCP      | 2049 | Mount target security group   |
    | Mount target SG | Inbound   | TCP      | 2049 | Compute security group        |

    Returns:
        The mount target security group ID.
    """
    compute_security_groups = _get_eks_security_groups()

    mount_target_sg_name = "gen3wf-s3files-mount-target-sg"
    existing = ec2_client.describe_security_groups(
        Filters=[{"Name": "group-name", "Values": [mount_target_sg_name]}]
    )["SecurityGroups"]

    if existing:
        mount_target_sg_id = existing[0]["GroupId"]
        logger.info(
            "Security group '%s' already exists (%s)",
            mount_target_sg_name,
            mount_target_sg_id,
        )
    else:
        response = ec2_client.create_security_group(
            GroupName=mount_target_sg_name,
            Description="S3 Files mount target SG -- allows inbound NFS (2049) from Funnel compute SGs only.",
            VpcId=vpc_id,
        )
        mount_target_sg_id = response["GroupId"]
        logger.info(
            "Created security group '%s' (%s)", mount_target_sg_name, mount_target_sg_id
        )

    # Inbound: mount target SG allows NFS from every compute SG, idempotently.
    try:
        ec2_client.authorize_security_group_ingress(
            GroupId=mount_target_sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": NFS_PORT,
                    "ToPort": NFS_PORT,
                    "UserIdGroupPairs": [
                        {"GroupId": compute_security_group_id}
                        for compute_security_group_id, _ in compute_security_groups
                    ],
                }
            ],
        )
        logger.info(
            "Authorized inbound TCP/%s on %s (%s) from %s",
            NFS_PORT,
            mount_target_sg_name,
            mount_target_sg_id,
            compute_security_groups,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidPermission.Duplicate":
            logger.info(
                "Inbound TCP/%s on %s (%s) from %s already exists; skipping.",
                NFS_PORT,
                mount_target_sg_name,
                mount_target_sg_id,
                compute_security_groups,
            )
        else:
            raise

    # Outbound: each compute SG allows NFS to the mount target SG, idempotently.
    for (
        compute_security_group_id,
        compute_security_group_name,
    ) in compute_security_groups:
        try:
            ec2_client.authorize_security_group_egress(
                GroupId=compute_security_group_id,
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": NFS_PORT,
                        "ToPort": NFS_PORT,
                        "UserIdGroupPairs": [{"GroupId": mount_target_sg_id}],
                    }
                ],
            )
            logger.info(
                "Authorized outbound TCP/%s on %s (%s) to %s (%s)",
                NFS_PORT,
                compute_security_group_id,
                compute_security_group_name,
                mount_target_sg_id,
                mount_target_sg_name,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidPermission.Duplicate":
                logger.info(
                    "Outbound TCP/%s on %s (%s) to %s (%s) already exists; skipping.",
                    NFS_PORT,
                    compute_security_group_id,
                    compute_security_group_name,
                    mount_target_sg_id,
                    mount_target_sg_name,
                )
            else:
                raise

    return mount_target_sg_id


# --------------------------------------------------------------------------- #
# IAM roles
# --------------------------------------------------------------------------- #


def _get_or_create_s3_files_bucket_role(bucket_name: str, region: str) -> str:
    """
    Get or create the IAM role that S3 Files itself assumes to read from / write to
    the source bucket and manage its EventBridge sync rules. This is the `roleArn`
    passed to `create_file_system`.

    NOTE: this is *not* the role attached to compute (EKS nodes) for mounting the
    file system -- that's handled separately.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-files-prereq-policies.html#s3-files-prereq-iam

    Returns:
        ARN of the (new or existing) IAM role.
    """
    # TODO: implementation
    return "arn:aws:iam::707767160287:role/Gen3WorkflowS3FilesPOC"


# ---------
# Wait for resource creation
# S3Files client does not have any built-in waiters as of yet.
# Writing custom waiters for our use case.
# ----------


def wait_for_file_system_ready(fs_id: str):
    fs_status, reason = get_filesystem_status(fs_id)
    logger.debug(f"Waiting for Filesystem: `{fs_id}`to be ready.")
    while fs_status in ["creating", "updating"]:
        time.sleep(2)
        fs_status, reason = get_filesystem_status(fs_id)
    if fs_status != "available":
        raise Exception(f"Failed to create file system.\nReason: {reason}")
    logger.debug(f"Filesystem: `{fs_id}` ready.")


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def setup_s3_filesystem(bucket_name: str) -> str:
    """
    Ensure an S3 Files file system exists for `bucket_name`, with one mount target
    per AZ the EKS cluster's nodes can run in, and the security groups needed for
    pods to reach those mount targets over NFS.

    Returns:
        The file system ID.
    """

    region = config["USER_BUCKETS_REGION"]
    role_arn = _get_or_create_s3_files_bucket_role(
        bucket_name=bucket_name, region=region
    )

    file_system_id = _create_s3_files_system(bucket_name, role_arn=role_arn)
    wait_for_file_system_ready(file_system_id)

    available_az_to_subnet_mapping = _get_available_az_to_subnet(
        discovery_tag=config["EKS_CLUSTER_NAME"]
    )
    mount_targets = list_mount_targets_for_file_system(file_system_id)

    # ASSUMPTION: this implementation currently requires the S3 bucket and the EKS
    # cluster to be in the same AWS region. We derive the mount target VPC from the
    # current compute environment (EKS cluster's VPC), which only works because the
    # S3 Files file system and its mount targets are expected to live in that same
    # region/VPC as the cluster.
    #
    # TODO: Support buckets in a different region than compute. This will require:
    #   1. Resolving the VPC (and mount target subnets) in the BUCKET's region rather
    #      than assuming it's the same as the compute VPC.
    #   2. Setting up cross-region connectivity (VPC peering or Transit Gateway)
    #      between the compute VPC and the bucket-region VPC, including route table
    #      updates on both sides.
    #   3. Allowing inbound NFS (TCP 2049) from EKS node/pod security group on the mount
    #      target security group in the bucket's region.
    mount_target_vpc_id = _get_vpc_id()

    mount_target_sg_id = _get_or_create_security_groups(vpc_id=mount_target_vpc_id)

    # Create new m.t.s of this file system ID for each missing az from the az_to_subnet_dict
    az_with_mount_targets = {mt["availabilityZoneId"] for mt in mount_targets}
    for az, subnet_id in available_az_to_subnet_mapping.items():
        if az in az_with_mount_targets:
            continue
        create_mount_target_for_file_system(
            file_system_id=file_system_id,
            subnet_id=subnet_id,
            mount_target_sg_id=mount_target_sg_id,
        )
    return file_system_id
