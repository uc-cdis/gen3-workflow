import json
from unittest.mock import patch

from conftest import TEST_USER_ID
from gen3workflow import aws_utils
from gen3workflow.config import config
from test_misc import mock_aws_services


def test_create_role_for_bucket_access_creates_role_when_missing(mock_aws_services):
    """
    Test aws_utils.iam.create_role is called when a new iam role is being created
    """

    role_name = f"gen3wf-localhost-{TEST_USER_ID}-funnel-role"

    # Create KMS key to make sure, key exists and is added to the policy
    kms_key_alias = f"alias/gen3wf-localhost-{TEST_USER_ID}"
    output = aws_utils.kms_client.create_key()
    kms_key_arn = output["KeyMetadata"]["Arn"]
    aws_utils.kms_client.create_alias(AliasName=kms_key_alias, TargetKeyId=kms_key_arn)

    # Spy on the method while still letting moto execute it
    with patch.object(
        aws_utils.iam_client,
        "create_role",
        wraps=aws_utils.iam_client.create_role,
    ) as create_role_spy, patch.object(
        aws_utils.iam_client,
        "put_role_policy",
        wraps=aws_utils.iam_client.put_role_policy,
    ) as put_policy_spy:

        # Act
        aws_utils.create_iam_role_for_bucket_access(TEST_USER_ID)

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

        actual_assume_role_json_string = aws_utils._json_normalized(
            actual_assume_role_policy
        )

        # Compute OIDC issuer from mocked EKS (non-deterministic, therefore can't be hardcoded)
        mock_oidc_token_url = aws_utils.eks_client.describe_cluster(
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
        expected_assume_role_json_string = aws_utils._json_normalized(
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
        actual_policy_json_string = aws_utils._json_normalized(actual_policy)

        expected_policy_json_string = aws_utils._json_normalized(expected_policy)
        assert expected_policy_json_string == actual_policy_json_string, (
            "PolicyDocument mismatch\n"
            f"EXPECTED:\n{json.dumps(expected_policy_json_string, indent=2, sort_keys=True)}\n\n"
            f"ACTUAL:\n{json.dumps(actual_policy_json_string, indent=2, sort_keys=True)}\n"
        )


def test_update_assume_role_policy_called_when_policy_updated(mock_aws_services):
    """
    Test aws_utils.iam.update_assume_role_policy is called when there is a policy update
    """
    # Force the role to exists AND policy to be different to trigger an update
    role_name = f"gen3wf-localhost-{TEST_USER_ID}-funnel-role"
    assume_role_policy_doc = {"Version": "2012-10-17", "Statement": []}
    aws_utils.iam_client.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(assume_role_policy_doc)
    )

    with patch.object(
        aws_utils.iam_client,
        "update_assume_role_policy",
        wraps=aws_utils.iam_client.update_assume_role_policy,
    ) as update_assume_role_spy:

        # Act
        aws_utils.create_iam_role_for_bucket_access(TEST_USER_ID)

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
    Test aws_utils.iam.update_assume_role_policy is NOT called when the policy is unchanged
    """

    # Compute OIDC issuer from mocked EKS (non-deterministic, therefore can't be hardcoded)
    mock_oidc_token_url = aws_utils.eks_client.describe_cluster(
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
    aws_utils.iam_client.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(assume_role_policy_doc)
    )
    # Spy on the method while still letting moto execute it
    with patch.object(
        aws_utils.iam_client,
        "update_assume_role_policy",
        wraps=aws_utils.iam_client.update_assume_role_policy,
    ) as update_assume_role_spy:

        # Act
        aws_utils.create_iam_role_for_bucket_access(TEST_USER_ID)

        # Assert it was NOT called
        assert (
            update_assume_role_spy.call_count == 0
        ), "Expected update_assume_role_policy NOT to be called"


def test_create_role_for_bucket_access_with_no_kms_enabled(
    monkeypatch, mock_aws_services
):
    """
    Test aws_utils.iam.create_role is called when a new iam role is being created
    """

    monkeypatch.setitem(aws_utils.config, "KMS_ENCRYPTION_ENABLED", False)

    # Create KMS key to make sure, key exists and is added to the policy
    kms_key_alias = f"alias/gen3wf-localhost-{TEST_USER_ID}"
    output = aws_utils.kms_client.create_key()
    kms_key_arn = output["KeyMetadata"]["Arn"]
    aws_utils.kms_client.create_alias(AliasName=kms_key_alias, TargetKeyId=kms_key_arn)

    # Spy on the method while still letting moto execute it
    with patch.object(
        aws_utils.iam_client,
        "put_role_policy",
        wraps=aws_utils.iam_client.put_role_policy,
    ) as put_policy_spy:

        # Act
        aws_utils.create_iam_role_for_bucket_access(TEST_USER_ID)

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
        actual_policy_doc = aws_utils._json_normalized(actual_policy)

        expected_policy_doc = aws_utils._json_normalized(expected_policy)
        assert expected_policy_doc == actual_policy_doc, (
            "PolicyDocument mismatch\n"
            f"EXPECTED:\n{json.dumps(expected_policy_doc, indent=2, sort_keys=True)}\n\n"
            f"ACTUAL:\n{json.dumps(actual_policy_doc, indent=2, sort_keys=True)}\n"
        )
