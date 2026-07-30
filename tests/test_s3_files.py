"""
Unit tests for `gen3workflow.aws.s3_files`.
"""

# pylint: disable=protected-access

import json
import time
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from gen3workflow.aws import clients, s3_files
from gen3workflow.config import config
from tests.test_misc import S3FilesResourceNotFoundException, mock_aws_services


def _client_error(code: str, message: str = "error", operation_name: str = "Operation"):
    """
    Build a real `botocore.exceptions.ClientError`, the way boto3 would raise one.
    """
    return ClientError(
        error_response={"Error": {"Code": code, "Message": message}},
        operation_name=operation_name,
    )


# --------------------------------------------------------------------------- #
# get_s3_files_system
# --------------------------------------------------------------------------- #


def test_get_s3_files_system_found(mock_aws_services):
    """
    If a file system already exists for the bucket's ARN, its ID is returned.
    """
    bucket_name = "test-bucket"
    bucket_arn = f"arn:aws:s3:::{bucket_name}"
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {
            "fileSystems": [
                {
                    "bucket": "arn:aws:s3:::some-other-bucket",
                    "fileSystemId": "fs-1",
                    "status": "available",
                },
                {"bucket": bucket_arn, "fileSystemId": "fs-2", "status": "available"},
            ]
        }
    ]
    clients.s3files_client.get_paginator.return_value = paginator

    result = s3_files.get_s3_files_system(bucket_name)

    assert result == "fs-2"
    clients.s3files_client.get_paginator.assert_called_once_with("list_file_systems")


def test_get_s3_files_system_not_found(mock_aws_services):
    """
    If no file system matches the bucket's ARN, `None` is returned.
    """
    paginator = MagicMock()
    paginator.paginate.return_value = [{"fileSystems": []}]
    clients.s3files_client.get_paginator.return_value = paginator

    assert s3_files.get_s3_files_system("test-bucket") is None


def test_get_s3_files_system_multiple_pages(mock_aws_services):
    """
    The match can be on a later page; pagination is followed to completion.
    """
    bucket_name = "test-bucket"
    bucket_arn = f"arn:aws:s3:::{bucket_name}"
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {
            "fileSystems": [
                {
                    "bucket": "arn:aws:s3:::other",
                    "fileSystemId": "fs-1",
                    "status": "available",
                }
            ]
        },
        {
            "fileSystems": [
                {"bucket": bucket_arn, "fileSystemId": "fs-2", "status": "available"}
            ]
        },
    ]
    clients.s3files_client.get_paginator.return_value = paginator

    assert s3_files.get_s3_files_system(bucket_name) == "fs-2"


def test_get_s3_files_system_client_error_reraises(mock_aws_services):
    """
    A `ClientError` while listing file systems is logged and re-raised, not swallowed.
    """
    clients.s3files_client.get_paginator.side_effect = _client_error(
        "InternalError", "boom", "ListFileSystems"
    )

    with pytest.raises(ClientError):
        s3_files.get_s3_files_system("test-bucket")


# --------------------------------------------------------------------------- #
# get_filesystem_status
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("empty_id", ["", None])
def test_get_filesystem_status_empty_id(empty_id, mock_aws_services):
    """
    An empty/`None` file_system_id short-circuits without calling AWS.
    """
    with pytest.raises(ValueError):
        status, message = s3_files.get_filesystem_status(empty_id)

    clients.s3files_client.get_file_system.assert_not_called()


def test_get_filesystem_status_success(mock_aws_services):
    """
    Happy path for getting file system status
    """
    clients.s3files_client.get_file_system.return_value = {
        "status": "available",
        "statusMessage": None,
    }

    status, message = s3_files.get_filesystem_status("fs-123")

    assert status == "available"
    assert message is None
    clients.s3files_client.get_file_system.assert_called_once_with(
        fileSystemId="fs-123"
    )


def test_get_filesystem_status_not_found(mock_aws_services):
    """
    A `ResourceNotFoundException` is translated into a `FileSystemNotFoundError` and propagated.
    """
    clients.s3files_client.get_file_system.side_effect = (
        S3FilesResourceNotFoundException()
    )
    with pytest.raises(s3_files.FileSystemNotFoundError):
        status, message = s3_files.get_filesystem_status("fs-missing")


def test_get_filesystem_status_generic_client_error(mock_aws_services):
    """
    Any other `ClientError` is also translated into a `(None, <message>)` tuple
    (unlike most other functions in this module, which re-raise).
    """
    clients.s3files_client.get_file_system.side_effect = _client_error(
        "InternalError", "server exploded", "GetFileSystem"
    )
    with pytest.raises(ClientError):
        status, message = s3_files.get_filesystem_status("fs-123")


# --------------------------------------------------------------------------- #
# get_mount_target_status / get_s3files_setup_status
#
# Both functions are currently `# TODO` stubs that unconditionally return
# "Not ready". These tests verify the underlying data is still fetched,
# so that once the TODOs are implemented, these tests will fail and call out
# the exact behavior that needs to be updated.
# --------------------------------------------------------------------------- #


def test_get_mount_target_status():
    """
    Test verifies whether mount target status is being called
    """
    with patch.object(
        s3_files, "list_mount_targets_for_file_system", return_value=[]
    ) as list_mts:
        result = s3_files.get_mount_target_status("fs-123")

    list_mts.assert_called_once_with("fs-123")
    assert result == "Not ready"


def test_get_s3files_setup_status():
    """
    Test verifies whether get s3files setup calls required dependent functions
    """
    with patch.object(
        s3_files, "get_filesystem_status", return_value=("available", None)
    ) as get_fs_status, patch.object(
        s3_files, "get_mount_target_status", return_value="Not ready"
    ) as get_mt_status:
        result = s3_files.get_s3files_setup_status("fs-123")

    get_fs_status.assert_called_once_with(file_system_id="fs-123")
    get_mt_status.assert_called_once_with("fs-123")
    assert result == "Not ready"


# --------------------------------------------------------------------------- #
# _create_s3_files_system
# --------------------------------------------------------------------------- #


def test_create_s3_files_system_success(mock_aws_services):
    """
    Tests S3Files create file system happy path.
    """
    clients.s3files_client.create_file_system.return_value = {"fileSystemId": "fs-new"}

    result = s3_files._create_s3_files_system(
        bucket_name="test-bucket",
        role_arn="arn:aws:iam::123456789012:role/s3files-role",
    )

    assert result == "fs-new"
    clients.s3files_client.create_file_system.assert_called_once_with(
        bucket="arn:aws:s3:::test-bucket",
        prefix="funnel-temp-files/",
        roleArn="arn:aws:iam::123456789012:role/s3files-role",
        tags=[{"Key": "Name", "Value": "gen3wf-localhost"}],
    )


def test_create_s3_files_system_client_error_reraises(mock_aws_services):
    """
    A `ClientError` while creating the file system is re-raised, not swallowed.
    """
    clients.s3files_client.create_file_system.side_effect = _client_error(
        "ValidationException", "bad bucket", "CreateFileSystem"
    )

    with pytest.raises(ClientError):
        s3_files._create_s3_files_system(
            bucket_name="test-bucket",
            role_arn="arn:aws:iam::123456789012:role/s3files-role",
        )


# --------------------------------------------------------------------------- #
# create_mount_target_for_file_system
# --------------------------------------------------------------------------- #


def test_create_mount_target_for_file_system_success(mock_aws_services):
    """
    Tests happy path for creating a mount target for a file system.
    """
    clients.s3files_client.create_mount_target.return_value = {
        "mountTargetId": "fsmt-1",
        "status": "creating",
    }

    s3_files.create_mount_target_for_file_system(
        file_system_id="fs-123", subnet_id="subnet-abc", mount_target_sg_id="sg-abc"
    )

    clients.s3files_client.create_mount_target.assert_called_once_with(
        fileSystemId="fs-123", subnetId="subnet-abc", securityGroups=["sg-abc"]
    )


def test_create_mount_target_for_file_system_client_error_reraises(
    mock_aws_services,
):
    """
    A `ClientError` while creating a mount target is re-raised, not swallowed.
    """
    clients.s3files_client.create_mount_target.side_effect = _client_error(
        "ValidationException", "bad subnet", "CreateMountTarget"
    )

    with pytest.raises(ClientError):
        s3_files.create_mount_target_for_file_system(
            file_system_id="fs-123", subnet_id="subnet-abc", mount_target_sg_id="sg-abc"
        )


# --------------------------------------------------------------------------- #
# list_mount_targets_for_file_system
# --------------------------------------------------------------------------- #


def test_list_mount_targets_for_file_system_flattens_pages(mock_aws_services):
    """
    Mount targets spread across multiple pages are flattened into a single list.
    """
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {"mountTargets": [{"mountTargetId": "fsmt-1"}]},
        {"mountTargets": [{"mountTargetId": "fsmt-2"}, {"mountTargetId": "fsmt-3"}]},
    ]
    clients.s3files_client.get_paginator.return_value = paginator

    result = s3_files.list_mount_targets_for_file_system("fs-123")

    assert [mt["mountTargetId"] for mt in result] == ["fsmt-1", "fsmt-2", "fsmt-3"]
    clients.s3files_client.get_paginator.assert_called_once_with("list_mount_targets")
    paginator.paginate.assert_called_once_with(fileSystemId="fs-123")


def test_list_mount_targets_for_file_system_empty(mock_aws_services):
    """
    An empty page of mount targets results in an empty list.
    """
    paginator = MagicMock()
    paginator.paginate.return_value = [{"mountTargets": []}]
    clients.s3files_client.get_paginator.return_value = paginator

    assert s3_files.list_mount_targets_for_file_system("fs-123") == []


def test_list_mount_targets_for_file_system_client_error_reraises(
    mock_aws_services,
):
    """
    A `ClientError` while listing mount targets is re-raised, not swallowed.
    """
    clients.s3files_client.get_paginator.side_effect = _client_error(
        "InternalError", "boom", "ListMountTargets"
    )

    with pytest.raises(ClientError):
        s3_files.list_mount_targets_for_file_system("fs-123")


# --------------------------------------------------------------------------- #
# _get_vpc_id
#
# moto's EKS mock does not populate `resourcesVpcConfig.vpcId` on
# `describe_cluster` (it only echoes back input fields, and `vpcId` is not a
# valid `create_cluster` input parameter -- it's server-generated on real AWS).
# So this is mocked directly rather than through moto.
# --------------------------------------------------------------------------- #


def test_get_vpc_id():
    """
    The VPC ID is read from the EKS cluster's `resourcesVpcConfig`.
    """
    fake_eks_client = MagicMock()
    fake_eks_client.describe_cluster.return_value = {
        "cluster": {"resourcesVpcConfig": {"vpcId": "vpc-abc123"}}
    }

    with patch.object(clients, "eks_client", fake_eks_client):
        result = s3_files._get_vpc_id()

    assert result == "vpc-abc123"
    fake_eks_client.describe_cluster.assert_called_once_with(
        name=config["EKS_CLUSTER_NAME"]
    )


# --------------------------------------------------------------------------- #
# _get_available_az_to_subnet
# --------------------------------------------------------------------------- #


def test_get_available_az_to_subnet(mock_aws_services):
    """
    Only subnets tagged for discovery are returned, mapped by availability zone.
    """

    # Create dummy VPC through moto with subnets and tags
    vpc_id = clients.ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

    discoverable_subnet = clients.ec2_client.create_subnet(
        VpcId=vpc_id, CidrBlock="10.0.1.0/24", AvailabilityZone="us-east-1a"
    )["Subnet"]
    clients.ec2_client.create_tags(
        Resources=[discoverable_subnet["SubnetId"]],
        Tags=[{"Key": "karpenter.sh/discovery", "Value": "test-cluster"}],
    )

    # a subnet without the discovery tag should not show up in the result
    other_subnet = clients.ec2_client.create_subnet(
        VpcId=vpc_id, CidrBlock="10.0.2.0/24", AvailabilityZone="us-east-1b"
    )["Subnet"]

    result = s3_files._get_available_az_to_subnet(discovery_tag="test-cluster")

    assert result == {
        discoverable_subnet["AvailabilityZoneId"]: discoverable_subnet["SubnetId"]
    }
    assert other_subnet["SubnetId"] not in result.values()


def test_get_available_az_to_subnet_no_matches(mock_aws_services):
    """
    No subnets tagged for discovery results in an empty mapping.
    """
    result = s3_files._get_available_az_to_subnet(discovery_tag="nonexistent-tag")
    assert result == {}


# --------------------------------------------------------------------------- #
# _get_eks_security_groups
# --------------------------------------------------------------------------- #


def test_get_eks_security_groups(mock_aws_services, monkeypatch):
    """
    Only security groups matching the EKS_SECURITY_GROUP_NAMES mentioned in the config are returned.
    """

    vpc_id = clients.ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

    workers_sg = clients.ec2_client.create_security_group(
        GroupName="test-cluster_EKS_workers_sg", Description="workers", VpcId=vpc_id
    )
    jupyter_sg = clients.ec2_client.create_security_group(
        GroupName="test-cluster_EKS_nodepool_jupyter_sg",
        Description="jupyter",
        VpcId=vpc_id,
    )
    # an unrelated security group should not be returned
    clients.ec2_client.create_security_group(
        GroupName="unrelated-sg", Description="unrelated", VpcId=vpc_id
    )

    monkeypatch.setitem(
        config,
        "EKS_SECURITY_GROUP_NAMES",
        ["test-cluster_EKS_workers_sg", "test-cluster_EKS_nodepool_jupyter_sg"],
    )

    result = s3_files._get_eks_security_groups()

    result_ids = {sg_id for sg_id, _ in result}
    assert result_ids == {workers_sg["GroupId"], jupyter_sg["GroupId"]}


def test_get_eks_security_groups_none_found(mock_aws_services):
    """
    No matching security groups results in an empty list.
    """
    assert s3_files._get_eks_security_groups() == []


# --------------------------------------------------------------------------- #
# _get_or_create_security_groups
# --------------------------------------------------------------------------- #


def test_get_or_create_security_groups_creates_new_sg(mock_aws_services):
    """
    When no mount target security group exists yet, one is created with the
    expected ingress/egress NFS rules.
    """
    vpc_id = clients.ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    compute_sg = clients.ec2_client.create_security_group(
        GroupName="test-cluster_EKS_workers_sg", Description="workers", VpcId=vpc_id
    )

    mount_target_sg_id = s3_files._get_or_create_security_groups(vpc_id=vpc_id)

    # the new mount target security group exists in this VPC:
    described = clients.ec2_client.describe_security_groups(
        Filters=[{"Name": "group-name", "Values": ["gen3wf-s3files-mount-target-sg"]}]
    )["SecurityGroups"]
    assert len(described) == 1
    assert described[0]["GroupId"] == mount_target_sg_id
    assert described[0]["VpcId"] == vpc_id

    # inbound NFS from the compute SG is allowed on the mount target SG:
    ip_permissions = described[0]["IpPermissions"]
    assert any(
        perm["FromPort"] == s3_files.NFS_PORT
        and perm["ToPort"] == s3_files.NFS_PORT
        and perm["IpProtocol"] == "tcp"
        and any(
            pair["GroupId"] == compute_sg["GroupId"]
            for pair in perm["UserIdGroupPairs"]
        )
        for perm in ip_permissions
    )

    # outbound NFS to the mount target SG is allowed on the compute SG:
    compute_sg_described = clients.ec2_client.describe_security_groups(
        GroupIds=[compute_sg["GroupId"]]
    )["SecurityGroups"][0]
    egress_permissions = compute_sg_described["IpPermissionsEgress"]
    assert any(
        perm.get("FromPort") == s3_files.NFS_PORT
        and perm.get("ToPort") == s3_files.NFS_PORT
        and any(
            pair["GroupId"] == mount_target_sg_id
            for pair in perm.get("UserIdGroupPairs", [])
        )
        for perm in egress_permissions
    )


def test_get_or_create_security_groups_reuses_existing_sg(mock_aws_services):
    """
    If the mount target security group already exists, it is reused (not
    recreated), but its ingress/egress rules are still (idempotently) ensured.
    """
    vpc_id = clients.ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    clients.ec2_client.create_security_group(
        GroupName="test-cluster_EKS_workers_sg", Description="workers", VpcId=vpc_id
    )
    existing_mount_target_sg = clients.ec2_client.create_security_group(
        GroupName="gen3wf-s3files-mount-target-sg", Description="existing", VpcId=vpc_id
    )

    with patch.object(
        clients.ec2_client,
        "create_security_group",
        wraps=clients.ec2_client.create_security_group,
    ) as create_sg_spy:
        result = s3_files._get_or_create_security_groups(vpc_id=vpc_id)

    assert result == existing_mount_target_sg["GroupId"]
    create_sg_spy.assert_not_called()


def test_get_or_create_security_groups_is_idempotent(mock_aws_services):
    """
    Calling this function twice (simulating a second bucket/file-system setup that
    reuses the same cluster) must not raise, even though both the ingress rule on
    the mount target SG and the egress rules on every compute SG will already
    exist on the second call (triggering the `InvalidPermission.Duplicate` code
    paths for both).
    """
    vpc_id = clients.ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    clients.ec2_client.create_security_group(
        GroupName="test-cluster_EKS_workers_sg", Description="workers", VpcId=vpc_id
    )

    first_result = s3_files._get_or_create_security_groups(vpc_id=vpc_id)
    # second call should not raise despite duplicate ingress/egress rules
    second_result = s3_files._get_or_create_security_groups(vpc_id=vpc_id)

    assert first_result == second_result


def test_get_or_create_security_groups_ingress_reraises_non_duplicate_error(
    mock_aws_services,
):
    """
    A non-duplicate `ClientError` on the ingress-rule call must propagate.
    """
    vpc_id = clients.ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    clients.ec2_client.create_security_group(
        GroupName="test-cluster_EKS_workers_sg", Description="workers", VpcId=vpc_id
    )

    with patch.object(
        clients.ec2_client,
        "authorize_security_group_ingress",
        side_effect=_client_error(
            "InvalidGroup.NotFound", "gone", "AuthorizeSecurityGroupIngress"
        ),
    ):
        with pytest.raises(ClientError) as exc_info:
            s3_files._get_or_create_security_groups(vpc_id=vpc_id)

    assert exc_info.value.response["Error"]["Code"] == "InvalidGroup.NotFound"


def test_get_or_create_security_groups_egress_reraises_non_duplicate_error(
    mock_aws_services,
):
    """
    A non-duplicate `ClientError` on the egress-rule call must propagate.
    """

    vpc_id = clients.ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    clients.ec2_client.create_security_group(
        GroupName="test-cluster_EKS_workers_sg", Description="workers", VpcId=vpc_id
    )

    with patch.object(
        clients.ec2_client,
        "authorize_security_group_egress",
        side_effect=_client_error(
            "InvalidGroup.NotFound", "gone", "AuthorizeSecurityGroupEgress"
        ),
    ):
        with pytest.raises(ClientError) as exc_info:
            s3_files._get_or_create_security_groups(vpc_id=vpc_id)

    assert exc_info.value.response["Error"]["Code"] == "InvalidGroup.NotFound"


# --------------------------------------------------------------------------- #
# _get_or_create_s3_files_bucket_role
# --------------------------------------------------------------------------- #


def test_get_or_create_s3_files_bucket_role_creates_new_role(mock_aws_services):
    """
    When no bucket role exists yet, one is created with the expected trust
    policy and inline access policy.
    """
    bucket_name = "test-bucket"
    region = "us-east-1"

    with patch.object(
        clients.iam_client,
        "create_role",
        wraps=clients.iam_client.create_role,
    ) as create_role_spy, patch.object(
        clients.iam_client,
        "put_role_policy",
        wraps=clients.iam_client.put_role_policy,
    ) as put_policy_spy:
        role_arn = s3_files._get_or_create_s3_files_bucket_role(
            bucket_name=bucket_name, region=region
        )

    assert role_arn.endswith(f"role/{bucket_name}-s3files-role")
    create_role_spy.assert_called_once()
    _, create_role_kwargs = create_role_spy.call_args
    assert create_role_kwargs["RoleName"] == f"{bucket_name}-s3files-role"

    trust_policy = json.loads(create_role_kwargs["AssumeRolePolicyDocument"])
    assert trust_policy["Statement"][0]["Principal"] == {
        "Service": "elasticfilesystem.amazonaws.com"
    }
    assert trust_policy["Statement"][0]["Action"] == "sts:AssumeRole"

    put_policy_spy.assert_called_once()
    _, put_policy_kwargs = put_policy_spy.call_args
    assert put_policy_kwargs["RoleName"] == f"{bucket_name}-s3files-role"
    assert put_policy_kwargs["PolicyName"] == "S3FilesBucketAccess"

    inline_policy = json.loads(put_policy_kwargs["PolicyDocument"])
    sids = {statement["Sid"] for statement in inline_policy["Statement"]}
    # the KMS statement is included unconditionally, regardless of whether KMS
    # encryption is enabled for this deployment
    assert "UseKmsKeyWithS3Files" in sids
    assert "S3BucketPermissions" in sids
    assert "S3ObjectPermissions" in sids


def test_get_or_create_s3_files_bucket_role_returns_existing_role(
    mock_aws_services,
):
    """
    If the role already exists, it is returned as-is and no new role/policy is
    created.
    """
    bucket_name = "test-bucket"
    role_name = f"{bucket_name}-s3files-role"
    existing_role = clients.iam_client.create_role(
        RoleName=role_name, AssumeRolePolicyDocument="{}"
    )
    expected_arn = existing_role["Role"]["Arn"]

    with patch.object(
        clients.iam_client,
        "create_role",
        wraps=clients.iam_client.create_role,
    ) as create_role_spy, patch.object(
        clients.iam_client,
        "put_role_policy",
        wraps=clients.iam_client.put_role_policy,
    ) as put_policy_spy:
        role_arn = s3_files._get_or_create_s3_files_bucket_role(
            bucket_name=bucket_name, region="us-east-1"
        )

    assert role_arn == expected_arn
    create_role_spy.assert_not_called()
    put_policy_spy.assert_not_called()


def test_get_or_create_s3_files_bucket_role_client_error_reraises(
    mock_aws_services,
):
    """
    A `ClientError` while creating the bucket role is re-raised, not swallowed.
    """
    with patch.object(
        clients.iam_client,
        "create_role",
        side_effect=_client_error("ServiceFailure", "boom", "CreateRole"),
    ):
        with pytest.raises(ClientError):
            s3_files._get_or_create_s3_files_bucket_role(
                bucket_name="test-bucket", region="us-east-1"
            )


# --------------------------------------------------------------------------- #
# wait_for_file_system_ready
# --------------------------------------------------------------------------- #


def test_wait_for_file_system_ready_already_available():
    """
    If the file system is already available, no polling/sleeping occurs.
    """
    with patch.object(
        s3_files, "get_filesystem_status", return_value=("available", None)
    ), patch.object(time, "sleep") as sleep_mock:
        s3_files.wait_for_file_system_ready("fs-123")

    sleep_mock.assert_not_called()


def test_wait_for_file_system_ready_polls_until_available():
    """
    The function polls (sleeping between calls) until the file system becomes available.
    """
    statuses = [("creating", None), ("updating", None), ("available", None)]

    with patch.object(
        s3_files, "get_filesystem_status", side_effect=statuses
    ) as get_status_mock, patch.object(time, "sleep") as sleep_mock:
        s3_files.wait_for_file_system_ready("fs-123")

    assert get_status_mock.call_count == 3
    assert sleep_mock.call_count == 2


def test_wait_for_file_system_ready_logs_status_message_while_polling():
    """
    While still `creating`/`updating`, a non-empty status message (`reason`) is
    logged on each poll rather than being dropped.
    """
    statuses = [
        ("creating", None),  # initial fetch, before the loop -- reason not checked
        ("creating", "provisioning underlying resources"),  # fetched inside the loop
        ("available", None),
    ]

    with patch.object(
        s3_files, "get_filesystem_status", side_effect=statuses
    ), patch.object(time, "sleep"), patch.object(
        s3_files.logger, "debug"
    ) as debug_mock:
        s3_files.wait_for_file_system_ready("fs-123")

    assert any(
        "provisioning underlying resources" in call_args.args[0]
        for call_args in debug_mock.call_args_list
    )


def test_wait_for_file_system_ready_raises_on_failure():
    """
    An `error` status causes the wait to raise, surfacing the failure reason.
    """
    with patch.object(
        s3_files,
        "get_filesystem_status",
        return_value=("error", "something went wrong"),
    ), patch.object(time, "sleep"):
        with pytest.raises(Exception, match="something went wrong"):
            s3_files.wait_for_file_system_ready("fs-123")


def test_wait_for_file_system_ready_file_system_not_found_reraises_immediately():
    """
    A `FileSystemNotFoundError` is not treated as transient; it's re-raised on
    the very first failure, without retrying or sleeping.
    """
    with patch.object(
        s3_files,
        "get_filesystem_status",
        side_effect=s3_files.FileSystemNotFoundError("fs not found"),
    ) as get_status_mock, patch.object(time, "sleep") as sleep_mock:
        with pytest.raises(s3_files.FileSystemNotFoundError):
            s3_files.wait_for_file_system_ready("fs-123")

    get_status_mock.assert_called_once_with("fs-123")
    sleep_mock.assert_not_called()


def test_wait_for_file_system_ready_recovers_from_transient_failure():
    """
    A transient (non-`FileSystemNotFoundError`) exception below the failure
    tolerance is retried rather than raised, and polling continues until the
    file system becomes available.
    """
    statuses = [Exception("transient blip"), ("available", None)]

    with patch.object(
        s3_files, "get_filesystem_status", side_effect=statuses
    ) as get_status_mock, patch.object(time, "sleep") as sleep_mock:
        s3_files.wait_for_file_system_ready("fs-123")

    assert get_status_mock.call_count == 2
    assert sleep_mock.call_count == 1


def test_wait_for_file_system_ready_raises_after_exceeding_failure_tolerance():
    """
    Once consecutive transient failures reach `max_consecutive_failure_tolerance`,
    the underlying exception is raised instead of continuing to retry.
    """
    with patch.object(
        s3_files,
        "get_filesystem_status",
        side_effect=Exception("boom"),
    ) as get_status_mock, patch.object(time, "sleep") as sleep_mock:
        with pytest.raises(Exception, match="boom"):
            s3_files.wait_for_file_system_ready(
                "fs-123", max_consecutive_failure_tolerance=2
            )

    assert get_status_mock.call_count == 2
    assert sleep_mock.call_count == 1


def test_wait_for_file_system_ready_times_out():
    """
    If the elapsed time exceeds `timeout_seconds`, a `TimeoutError` is raised
    without ever calling `get_filesystem_status`.
    """
    with patch.object(time, "monotonic", side_effect=[0, 5]), patch.object(
        s3_files, "get_filesystem_status"
    ) as get_status_mock, patch.object(time, "sleep") as sleep_mock:
        with pytest.raises(TimeoutError, match="Timed out"):
            s3_files.wait_for_file_system_ready("fs-123", timeout_seconds=1)

    get_status_mock.assert_not_called()
    sleep_mock.assert_not_called()


# --------------------------------------------------------------------------- #
# setup_s3_filesystem (orchestration)
# --------------------------------------------------------------------------- #


def test_setup_s3_filesystem_orchestrates_role_and_filesystem_creation():
    """
    The bucket role is created/fetched first, then used to create the file system.
    """
    with patch.object(
        s3_files,
        "_get_or_create_s3_files_bucket_role",
        return_value="arn:aws:iam::123456789012:role/test-bucket-s3files-role",
    ) as get_role_mock, patch.object(
        s3_files, "_create_s3_files_system", return_value="fs-new"
    ) as create_fs_mock:
        result = s3_files.setup_s3_filesystem("test-bucket")

    assert result == "fs-new"
    get_role_mock.assert_called_once_with(
        bucket_name="test-bucket", region=config["USER_BUCKETS_REGION"]
    )
    create_fs_mock.assert_called_once_with(
        "test-bucket",
        role_arn="arn:aws:iam::123456789012:role/test-bucket-s3files-role",
    )


# --------------------------------------------------------------------------- #
# provision_mount_targets (orchestration)
# --------------------------------------------------------------------------- #


def test_provision_mount_targets_creates_missing_and_skips_existing():
    """
    One AZ already has a mount target and should be skipped; the other AZ is
    missing one and a mount target should be created for it.
    """
    az_to_subnet = {"az-1": "subnet-1", "az-2": "subnet-2"}
    existing_mount_targets = [{"availabilityZoneId": "az-1", "mountTargetId": "fsmt-1"}]

    with patch.object(
        s3_files, "_get_available_az_to_subnet", return_value=az_to_subnet
    ), patch.object(s3_files, "wait_for_file_system_ready") as wait_mock, patch.object(
        s3_files,
        "list_mount_targets_for_file_system",
        return_value=existing_mount_targets,
    ) as list_mts_mock, patch.object(
        s3_files, "_get_vpc_id", return_value="vpc-abc"
    ), patch.object(
        s3_files, "_get_or_create_security_groups", return_value="sg-abc"
    ) as get_sgs_mock, patch.object(
        s3_files, "create_mount_target_for_file_system"
    ) as create_mt_mock:
        result = s3_files.provision_mount_targets("fs-123")

    assert result == "fs-123"
    wait_mock.assert_called_once_with("fs-123")
    list_mts_mock.assert_called_once_with("fs-123")
    get_sgs_mock.assert_called_once_with(vpc_id="vpc-abc")

    # only az-2 (missing a mount target) should trigger a create call
    create_mt_mock.assert_called_once_with(
        file_system_id="fs-123", subnet_id="subnet-2", mount_target_sg_id="sg-abc"
    )


def test_provision_mount_targets_no_existing_mount_targets():
    """
    When no mount targets exist yet, one is created per available AZ/subnet.
    """
    az_to_subnet = {"az-1": "subnet-1", "az-2": "subnet-2"}

    with patch.object(
        s3_files, "_get_available_az_to_subnet", return_value=az_to_subnet
    ), patch.object(s3_files, "wait_for_file_system_ready"), patch.object(
        s3_files, "list_mount_targets_for_file_system", return_value=[]
    ), patch.object(
        s3_files, "_get_vpc_id", return_value="vpc-abc"
    ), patch.object(
        s3_files, "_get_or_create_security_groups", return_value="sg-abc"
    ), patch.object(
        s3_files, "create_mount_target_for_file_system"
    ) as create_mt_mock:
        s3_files.provision_mount_targets("fs-123")

    assert create_mt_mock.call_count == 2
    create_mt_mock.assert_any_call(
        file_system_id="fs-123", subnet_id="subnet-1", mount_target_sg_id="sg-abc"
    )
    create_mt_mock.assert_any_call(
        file_system_id="fs-123", subnet_id="subnet-2", mount_target_sg_id="sg-abc"
    )


def test_provision_mount_targets_all_azs_already_covered():
    """
    When every AZ already has a mount target, no new mount targets are created.
    """
    az_to_subnet = {"az-1": "subnet-1"}
    existing_mount_targets = [{"availabilityZoneId": "az-1", "mountTargetId": "fsmt-1"}]

    with patch.object(
        s3_files, "_get_available_az_to_subnet", return_value=az_to_subnet
    ), patch.object(s3_files, "wait_for_file_system_ready"), patch.object(
        s3_files,
        "list_mount_targets_for_file_system",
        return_value=existing_mount_targets,
    ), patch.object(
        s3_files, "_get_vpc_id", return_value="vpc-abc"
    ), patch.object(
        s3_files, "_get_or_create_security_groups", return_value="sg-abc"
    ), patch.object(
        s3_files, "create_mount_target_for_file_system"
    ) as create_mt_mock:
        result = s3_files.provision_mount_targets("fs-123")

    create_mt_mock.assert_not_called()
    assert result == "fs-123"
