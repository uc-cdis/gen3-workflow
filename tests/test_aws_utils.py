import json
from unittest.mock import patch

import pytest

from gen3workflow.aws import aws_utils, bucket, clients
from gen3workflow.aws.aws_utils import OUTPUTS_ARE_READY_CACHE, are_outputs_ready
from gen3workflow.config import config
from tests.conftest import (
    TEST_USER_ID,
    TEST_USER_TOKEN,
    remove_bucket_policy_and_put_object,
)


def test_create_role_for_bucket_access_creates_role_when_missing(mock_aws_services):
    """
    Test aws_utils.iam.create_role is called when a new iam role is being created
    """

    role_name = f"gen3wf-localhost-{TEST_USER_ID}-funnel-role"

    # Create KMS key to make sure, key exists and is added to the policy
    kms_key_alias = f"alias/gen3wf-localhost-{TEST_USER_ID}"
    output = clients.kms_client.create_key()
    kms_key_arn = output["KeyMetadata"]["Arn"]
    clients.kms_client.create_alias(AliasName=kms_key_alias, TargetKeyId=kms_key_arn)

    # Spy on the method while still letting moto execute it
    with patch.object(
        clients.iam_client,
        "create_role",
        wraps=clients.iam_client.create_role,
    ) as create_role_spy, patch.object(
        clients.iam_client,
        "put_role_policy",
        wraps=clients.iam_client.put_role_policy,
    ) as put_policy_spy:

        # Act
        bucket.create_iam_role_for_funnel_bucket_access(TEST_USER_ID)

        # IAM role doesn't exist by default since the mocks are isolated per tests
        # Assert create_role was called
        create_role_spy.assert_called_once(), "Expected create_role to be called"

        # Inspect the actual call arguments
        _, kwargs = create_role_spy.call_args

        assert kwargs["RoleName"] == role_name
        assert isinstance(
            kwargs["AssumeRolePolicyDocument"], str
        ), "Must be JSON string"
        actual_assume_role_policy = json.loads(
            kwargs["AssumeRolePolicyDocument"]
        )  # raises if invalid JSON

        actual_assume_role_json_string = aws_utils.dict_to_sorted_json_str(
            actual_assume_role_policy
        )

        # Compute OIDC issuer from mocked EKS (non-deterministic, therefore can't be hardcoded)
        mock_oidc_token_url = clients.eks_client.describe_cluster(
            name=config["EKS_CLUSTER_NAME"]
        )["cluster"]["identity"]["oidc"]["issuer"].replace("https://", "")
        # Build the same assume role policy doc as the function will build
        expected_assume_role_policy = {
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
                        "Federated": f"arn:aws:iam::123456789012:oidc-provider/{mock_oidc_token_url}"
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            f"{mock_oidc_token_url}:sub": f"system:serviceaccount:test-namespace:gen3wf-localhost-{TEST_USER_ID}-worker-sa",
                            f"{mock_oidc_token_url}:aud": "sts.amazonaws.com",
                        }
                    },
                },
            ],
        }
        expected_assume_role_json_string = aws_utils.dict_to_sorted_json_str(
            expected_assume_role_policy
        )
        assert expected_assume_role_json_string == actual_assume_role_json_string, (
            "AssumeRolePolicyDocument mismatch\n"
            f"EXPECTED:\n{json.dumps(expected_assume_role_policy, indent=2, sort_keys=True)}\n\n"
            f"ACTUAL:\n{json.dumps(actual_assume_role_policy, indent=2, sort_keys=True)}\n"
        )

        assert "Tags" in kwargs
        assert {
            "Key": "Name",
            "Value": aws_utils.get_safe_name_from_hostname(user_id=None),
        } in kwargs["Tags"]

        expected_policy_name = f"gen3wf-localhost-{TEST_USER_ID}-funnel-role-s3-access"
        expected_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:ListBucket",
                        "s3:GetBucketLocation",
                    ],
                    "Resource": f"arn:aws:s3:::gen3wf-localhost-{TEST_USER_ID}",
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:PutObject",
                        "s3:GetObject",
                        "s3:DeleteObject",
                    ],
                    "Resource": f"arn:aws:s3:::gen3wf-localhost-{TEST_USER_ID}/*",
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "kms:Decrypt",
                        "kms:Encrypt",
                        "kms:GenerateDataKey*",
                    ],
                    "Resource": kms_key_arn,
                },
            ],
        }
        _, put_role_policy_spy_kwargs = put_policy_spy.call_args
        assert put_role_policy_spy_kwargs["PolicyName"] == expected_policy_name
        assert put_role_policy_spy_kwargs["RoleName"] == role_name
        assert isinstance(
            put_role_policy_spy_kwargs["PolicyDocument"], str
        ), "Must be JSON string"

        actual_policy = json.loads(
            put_role_policy_spy_kwargs["PolicyDocument"]
        )  # raises if invalid JSON
        actual_policy_json_string = aws_utils.dict_to_sorted_json_str(actual_policy)

        expected_policy_json_string = aws_utils.dict_to_sorted_json_str(expected_policy)
        assert expected_policy_json_string == actual_policy_json_string, (
            "PolicyDocument mismatch\n"
            f"EXPECTED:\n{json.dumps(expected_policy_json_string, indent=2, sort_keys=True)}\n\n"
            f"ACTUAL:\n{json.dumps(actual_policy_json_string, indent=2, sort_keys=True)}\n"
        )


def test_update_assume_role_policy_called_when_policy_updated(mock_aws_services):
    """
    Test clients.iam.update_assume_role_policy is called when there is a policy update
    """
    # Force the role to exists AND policy to be different to trigger an update
    role_name = f"gen3wf-localhost-{TEST_USER_ID}-funnel-role"
    assume_role_policy_doc = {"Version": "2012-10-17", "Statement": []}
    clients.iam_client.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(assume_role_policy_doc)
    )

    # Create KMS key to make sure, key exists and is added to the policy
    kms_key_alias = f"alias/gen3wf-localhost-{TEST_USER_ID}"
    output = clients.kms_client.create_key()
    kms_key_arn = output["KeyMetadata"]["Arn"]
    clients.kms_client.create_alias(AliasName=kms_key_alias, TargetKeyId=kms_key_arn)

    with patch.object(
        clients.iam_client,
        "update_assume_role_policy",
        wraps=clients.iam_client.update_assume_role_policy,
    ) as update_assume_role_spy:

        # Act
        bucket.create_iam_role_for_funnel_bucket_access(TEST_USER_ID)

        # Assert it was called
        assert (
            update_assume_role_spy.called
        ), "Expected update_assume_role_policy to be called"

        # Inspect the actual call arguments
        _, kwargs = update_assume_role_spy.call_args

        assert kwargs["RoleName"] == role_name
        assert isinstance(kwargs["PolicyDocument"], str), "Must be JSON string"
        json.loads(kwargs["PolicyDocument"])  # must be valid JSON


def test_does_not_update_assume_role_policy_when_unchanged(mock_aws_services):
    """
    Test clients.iam.update_assume_role_policy is NOT called when the policy is unchanged
    """
    # Create KMS key to make sure, key exists and is added to the policy
    kms_key_alias = f"alias/gen3wf-localhost-{TEST_USER_ID}"
    output = clients.kms_client.create_key()
    kms_key_arn = output["KeyMetadata"]["Arn"]
    clients.kms_client.create_alias(AliasName=kms_key_alias, TargetKeyId=kms_key_arn)

    # Compute OIDC issuer from mocked EKS (non-deterministic, therefore can't be hardcoded)
    mock_oidc_token_url = clients.eks_client.describe_cluster(
        name=config["EKS_CLUSTER_NAME"]
    )["cluster"]["identity"]["oidc"]["issuer"].replace("https://", "")
    # Build the same assume role policy doc as the function will build
    assume_role_policy_doc = {
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
                    "Federated": f"arn:aws:iam::123456789012:oidc-provider/{mock_oidc_token_url}"
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        f"{mock_oidc_token_url}:sub": f"system:serviceaccount:test-namespace:gen3wf-localhost-{TEST_USER_ID}-worker-sa",
                        f"{mock_oidc_token_url}:aud": "sts.amazonaws.com",
                    }
                },
            },
        ],
    }
    # Force the "role exists AND policy remains same" branch
    role_name = f"gen3wf-localhost-{TEST_USER_ID}-funnel-role"
    clients.iam_client.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(assume_role_policy_doc)
    )
    # Spy on the method while still letting moto execute it
    with patch.object(
        clients.iam_client,
        "update_assume_role_policy",
        wraps=clients.iam_client.update_assume_role_policy,
    ) as update_assume_role_spy:

        # Act
        bucket.create_iam_role_for_funnel_bucket_access(TEST_USER_ID)

        # Assert it was NOT called
        assert (
            update_assume_role_spy.call_count == 0
        ), "Expected update_assume_role_policy NOT to be called"


def test_create_role_for_bucket_access_with_no_kms_enabled(
    monkeypatch, mock_aws_services
):
    """
    Test clients.iam.create_role is called when a new iam role is being created
    """

    monkeypatch.setitem(bucket.config, "KMS_ENCRYPTION_ENABLED", False)

    # Create KMS key to make sure, the policy is not updated when
    # KMS is diabled, despite a key being present
    kms_key_alias = f"alias/gen3wf-localhost-{TEST_USER_ID}"
    output = clients.kms_client.create_key()
    kms_key_arn = output["KeyMetadata"]["Arn"]
    clients.kms_client.create_alias(AliasName=kms_key_alias, TargetKeyId=kms_key_arn)

    # Spy on the method while still letting moto execute it
    with patch.object(
        clients.iam_client,
        "put_role_policy",
        wraps=clients.iam_client.put_role_policy,
    ) as put_policy_spy:

        # Act
        bucket.create_iam_role_for_funnel_bucket_access(TEST_USER_ID)

        expected_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:ListBucket",
                        "s3:GetBucketLocation",
                    ],
                    "Resource": f"arn:aws:s3:::gen3wf-localhost-{TEST_USER_ID}",
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:PutObject",
                        "s3:GetObject",
                        "s3:DeleteObject",
                    ],
                    "Resource": f"arn:aws:s3:::gen3wf-localhost-{TEST_USER_ID}/*",
                },
                # No policy related to KMS key in the expected policy document
            ],
        }
        _, put_role_policy_spy_kwargs = put_policy_spy.call_args
        assert isinstance(
            put_role_policy_spy_kwargs["PolicyDocument"], str
        ), "Must be JSON string"

        actual_policy = json.loads(
            put_role_policy_spy_kwargs["PolicyDocument"]
        )  # raises if invalid JSON
        actual_policy_doc = aws_utils.dict_to_sorted_json_str(actual_policy)

        expected_policy_doc = aws_utils.dict_to_sorted_json_str(expected_policy)
        assert expected_policy_doc == actual_policy_doc, (
            "PolicyDocument mismatch\n"
            f"EXPECTED:\n{json.dumps(expected_policy_doc, indent=2, sort_keys=True)}\n\n"
            f"ACTUAL:\n{json.dumps(actual_policy_doc, indent=2, sort_keys=True)}\n"
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state",
    [
        "all_ready",
        "not_present",
        "wrong_bucket",
        "wrong_size",
        "missing_url",
        "missing_size",
        "skip_next_files",
    ],
)
async def test_are_outputs_ready(
    client, access_token_patcher, mock_aws_services, state
):
    """
    Check `are_outputs_ready`'s functionality and returned values
    """
    # create the bucket if it doesn't exist
    res = await client.get(
        "/storage/setup", headers={"Authorization": f"bearer {TEST_USER_TOKEN}"}
    )
    assert res.status_code == 200, res.text
    bucket = res.json()["bucket"]

    # create the expected output file in the bucket
    file_contents = b"Dummy file contents"
    size = str(len(file_contents))
    ready_file = {
        "url": f"s3://{bucket}/ready",
        "path": "file.txt",
        "size_bytes": size,
    }
    ready_log = f"Output 's3://{bucket}/ready' of expected size {size} is present with size {size}: ready"
    remove_bucket_policy_and_put_object(bucket=bucket, key="ready", body=file_contents)

    not_present_file = {
        "url": f"s3://{bucket}/not_present",
        "path": "file.txt",
        "size_bytes": size,
    }
    not_present_log = (
        f"Output '{not_present_file['url']}' is not present in the bucket: not ready"
    )

    expected_logs = []
    if state == "all_ready":
        outputs = [ready_file, ready_file]
        expected_logs = [ready_log, ready_log]
    elif state == "not_present":
        outputs = [not_present_file]
        expected_logs = [not_present_log]
    elif state == "wrong_bucket":
        outputs = [
            {
                "url": f"s3://some-bucket/wrong_bucket",
                "path": "file.txt",
                "size_bytes": size,
            }
        ]
        expected_logs = [
            f"Output '{outputs[0]['url']}' is not in user's bucket '{bucket}': assuming it's ready"
        ]
    elif state == "wrong_size":
        outputs = [
            {
                "url": f"s3://{bucket}/ready",
                "path": "file.txt",
                "size_bytes": str(len(file_contents) + 2),
            }
        ]
        expected_logs = [
            f"Output '{outputs[0]['url']}' of expected size {outputs[0]['size_bytes']} is present with size {size}: not ready"
        ]
    elif state == "missing_url":
        outputs = [{"path": "file.txt", "size_bytes": size}]
        expected_logs = [
            f"Output {outputs[0]} is missing 'url' field: assuming it's ready"
        ]
    elif state == "missing_size":
        outputs = [{"url": f"s3://{bucket}/ready", "path": "file.txt"}]
        expected_logs = [
            f"Output '{outputs[0]['url']}' is present and missing 'size_bytes' field: assuming it's ready"
        ]
    elif state == "skip_next_files":
        outputs = [
            ready_file,
            not_present_file,
            {"url": f"s3://{bucket}/should_be_skipped"},
        ]
        expected_logs = [
            ready_log,
            not_present_log,
            f"Not checked: '{outputs[2]['url']}'",
        ]

    # call `are_outputs_ready` and check the returned values
    ready, logs = are_outputs_ready(
        TEST_USER_ID,
        f"test-task-id-{state}",
        outputs,
    )
    expected_ready = state in [
        "all_ready",
        "wrong_bucket",
        "missing_url",
        "missing_size",
    ]
    assert (
        ready == expected_ready
    ), f"`are_outputs_ready` should have returned ready={state == "all_ready"}. Logs: {logs}"
    assert logs == expected_logs


@pytest.mark.asyncio
async def test_are_outputs_ready_cache(client, access_token_patcher, mock_aws_services):
    """
    Check the `OUTPUTS_ARE_READY_CACHE`'s functionality
    """
    # create the bucket if it doesn't exist
    res = await client.get(
        "/storage/setup", headers={"Authorization": f"bearer {TEST_USER_TOKEN}"}
    )
    assert res.status_code == 200, res.text
    bucket = res.json()["bucket"]

    file_contents = b"Dummy file contents"
    size = str(len(file_contents))
    ready_file = {
        "url": f"s3://{bucket}/ready",
        "path": "file.txt",
        "size_bytes": size,
    }

    # the output file is not in the bucket, so `are_outputs_ready` should return "ready=False".
    # nothing should be cached since the outputs are not ready.
    task_id = "test-task-id"
    ready, logs = are_outputs_ready(
        TEST_USER_ID,
        task_id,
        [ready_file],
    )
    assert (
        ready == False
    ), f"`are_outputs_ready` should have returned ready=False. Logs: {logs}"
    assert logs == [
        f"Output 's3://{bucket}/ready' is not present in the bucket: not ready"
    ]
    assert OUTPUTS_ARE_READY_CACHE == set()

    # on the 2nd try, `are_outputs_ready` should be looking for the output file again
    ready, logs = are_outputs_ready(
        TEST_USER_ID,
        task_id,
        [ready_file],
    )
    assert (
        ready == False
    ), f"`are_outputs_ready` should have returned ready=False. Logs: {logs}"
    assert logs == [
        f"Output 's3://{bucket}/ready' is not present in the bucket: not ready"
    ]
    assert OUTPUTS_ARE_READY_CACHE == set()

    # create the expected output file in the bucket
    remove_bucket_policy_and_put_object(bucket=bucket, key="ready", body=file_contents)

    # `are_outputs_ready` should now find the output file and return "ready=True".
    # the task ID should be cached since the outputs are ready.
    ready, logs = are_outputs_ready(
        TEST_USER_ID,
        task_id,
        [ready_file],
    )
    assert (
        ready == True
    ), f"`are_outputs_ready` should have returned ready=True. Logs: {logs}"
    assert logs == [
        f"Output 's3://{bucket}/ready' of expected size {size} is present with size {size}: ready"
    ]
    assert OUTPUTS_ARE_READY_CACHE == {task_id}

    # on the 2nd try after uploading the output file, `are_outputs_ready` should use the cached
    # result and not look for the output file again (so the returned logs should be empty)
    ready, logs = are_outputs_ready(
        TEST_USER_ID,
        task_id,
        [ready_file],
    )
    assert (
        ready == True
    ), f"`are_outputs_ready` should have returned ready=True. Logs: {logs}"
    assert logs == []
    assert OUTPUTS_ARE_READY_CACHE == {task_id}


@pytest.mark.asyncio
async def test_are_outputs_ready_size_bytes_0(
    client, access_token_patcher, mock_aws_services
):
    """
    Check that `are_outputs_ready` handles `size_bytes = 0` which may be set by Funnel workers
    """
    # create the bucket if it doesn't exist
    res = await client.get(
        "/storage/setup", headers={"Authorization": f"bearer {TEST_USER_TOKEN}"}
    )
    assert res.status_code == 200, res.text
    bucket = res.json()["bucket"]

    # create the output directory and file in the bucket
    remove_bucket_policy_and_put_object(
        bucket=bucket, key="ready/file.txt", body=b"Dummy file contents"
    )

    # the task output lists the directory "ready", not the file "ready/file.txt"
    ready, logs = are_outputs_ready(
        TEST_USER_ID,
        "test-task-id",
        [{"url": f"s3://{bucket}/ready", "path": "file.txt", "size_bytes": 0}],
    )
    assert (
        ready == True
    ), f"`are_outputs_ready` should have returned ready=True. Logs: {logs}"
    assert logs == [
        f"Output {{'url': 's3://{bucket}/ready', 'path': 'file.txt', 'size_bytes': 0}} has 'size_bytes' 0: assuming it's a directory and it's ready"
    ]
