import json
from collections import deque
from typing import Union
from urllib.parse import urlparse

from botocore.exceptions import ClientError

from gen3workflow import logger
from gen3workflow.aws import clients
from gen3workflow.config import config

# The cache set allows fast lookups. We also maintain a deque to manage cache size.
OUTPUTS_ARE_READY_CACHE: set[str] = set()
OUTPUTS_ARE_READY_CACHE_ORDER = deque(maxlen=config["OUTPUTS_ARE_READY_CACHE_MAX_SIZE"])


def dict_to_sorted_json_str(obj: dict) -> str:
    """
    Reads a Python dict and returns a JSON string with ordered keys
    Use case: when comparing JSON objects returned by AWS, comparisons are deterministic and less flaky
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def get_safe_name_from_hostname(
    principal_id: Union[str, None], reserved_length: int = 0
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
        principal_id (str | None): The user or client's unique Gen3 ID. If None, will not be included in the safe name.
        reserved_length (int): Number of characters to reserve for prefixes/suffixes.

    Returns:
        str: safe name
    """
    escaped_hostname = config["HOSTNAME"].replace(".", "-")
    safe_name = f"gen3wf-{escaped_hostname}"
    max_chars = 63 - reserved_length
    if principal_id:
        # client IDs (used as the user ID for `client_credentials` tokens) may contain uppercase
        # characters, which are not allowed in S3 bucket or k8s service account names
        principal_id = principal_id.lower()
        max_chars = max_chars - len(f"-{principal_id}")
    if len(safe_name) > max_chars:
        safe_name = safe_name[:max_chars]
    if principal_id:
        safe_name = f"{safe_name}-{principal_id}"
    return safe_name


def get_worker_sa_name(principal_id: str) -> str:
    """
    Generate the name of the Kubernetes service account used by worker pods for the specified user.

    Args:
        principal_id (str): The user or client's unique Gen3 ID
    Returns:
        str: service account name
    """
    safe_name = get_safe_name_from_hostname(
        principal_id, reserved_length=len("-worker-sa")
    )
    return f"{safe_name}-worker-sa"


def get_bucket_name_from_principal_id(principal_id: str) -> str:
    """
    Generate the S3 bucket name for the specified user or client.

    Args:
        principal_id (str): The user or client's unique Gen3 ID
    Returns:
        str: S3 bucket name
    """
    # Abstracted for future flexibility — currently same as safe name.
    return get_safe_name_from_hostname(principal_id)


def are_outputs_ready(principal_id: str, task_id, outputs: list):
    """
    Check if all the files in the provided list of outputs are up to date in the user's bucket.
    Once all the outputs are ready, the result is cached to avoid unnecessary S3 requests.

    Returns:
        tuple (bool, list[str]): whether all outputs are ready, and any detailed logs to return to
            the user
    """
    if task_id in OUTPUTS_ARE_READY_CACHE:
        return True, []

    user_bucket_name = get_bucket_name_from_principal_id(principal_id)
    all_ready = True
    logs = []
    for output in outputs:
        if not output.get("url"):
            logs.append(f"Output {output} is missing 'url' field: assuming it's ready")
            continue
        if output.get("size_bytes") == 0:
            logs.append(
                f"Output {output} has 'size_bytes' 0: assuming it's a directory and it's ready"
            )
            continue
        if not all_ready:
            # if one file is not ready, skip checking the rest of the files
            logs.append(f"Not checked: '{output['url']}'")
            continue
        parsed_url = urlparse(output["url"])
        if parsed_url.netloc != user_bucket_name:
            logs.append(
                f"Output '{output['url']}' is not in user's bucket '{user_bucket_name}': assuming it's ready"
            )
            continue
        try:
            response = clients.s3_client.head_object(
                Bucket=parsed_url.netloc, Key=parsed_url.path.lstrip("/")
            )
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "404":
                raise
            logs.append(
                f"Output '{output['url']}' is not present in the bucket: not ready"
            )
            all_ready = False
        else:
            if not output.get("size_bytes"):
                logs.append(
                    f"Output '{output['url']}' is present and missing 'size_bytes' field: assuming it's ready"
                )
                continue
            # `size_bytes` in the GA4GH TES spec is a string and `ContentLength` is an int: convert
            all_ready = str(output["size_bytes"]) == str(response["ContentLength"])
            logs.append(
                f"Output '{output['url']}' of expected size {output['size_bytes']} is present with size {response['ContentLength']}: {'' if all_ready else 'not '}ready"
            )

    if all_ready:
        # When the deque is full, it silently drops the oldest item.
        # We manually remove the oldest value from the cache.
        if (
            len(OUTPUTS_ARE_READY_CACHE_ORDER)
            == config["OUTPUTS_ARE_READY_CACHE_MAX_SIZE"]
        ):
            oldest = OUTPUTS_ARE_READY_CACHE_ORDER[0]
            OUTPUTS_ARE_READY_CACHE.remove(oldest)

        OUTPUTS_ARE_READY_CACHE_ORDER.append(task_id)
        OUTPUTS_ARE_READY_CACHE.add(task_id)

    return all_ready, logs


def create_or_update_iam_role(
    principal_id: str,
    role_name: str,
    role_description: str,
    role_owner: str,
    trust_policy: dict,
    role_policy_name: str,
    role_policy: dict,
) -> str:
    """
    Create or update an IAM role.

    Args:
        principal_id (str): The user or client's unique Gen3 ID
        role_name (str): Name of the role to create or update
        role_description (str): Descrition of the role to create (note: not currently used if
            updating)
        role_owner (str): A name for the entity using the associated IAM role, if relevant
        role_policy_name (str): Name of the IAM policy to attach to the role
        trust_policy (dict): Assume role policy to attach to the role
        role_policy (dict): IAM policy to attach to the role

    Returns:
        str: ARN of the (new or existing) IAM role

    Raises:
        Exception: If there is an error during the creation or updating of the IAM role or policy
    """
    try:
        existing_role = clients.iam_client.get_role(RoleName=role_name)
        role_arn = existing_role["Role"]["Arn"]
        logger.info(f"IAM role '{role_name}' already exists ({role_arn})")
        existing_trust_policy = existing_role["Role"]["AssumeRolePolicyDocument"]
        if dict_to_sorted_json_str(existing_trust_policy) != dict_to_sorted_json_str(
            trust_policy
        ):
            clients.iam_client.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(trust_policy),
            )
        else:
            logger.debug("Role trust policy is already up to date")
    except clients.iam_client.exceptions.NoSuchEntityException as e:
        existing_role = None
        try:
            response = clients.iam_client.create_role(
                RoleName=role_name,
                Description=role_description,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
            )
            role_arn = response["Role"]["Arn"]
            logger.info(f"Created IAM role '{role_name}' ({role_arn})")
        except ClientError as e:
            logger.error(
                f"Failed to create IAM role '{role_name}': {e.response['Error']['Message']}"
            )
            raise

    # Update the role tags - this could be done during `create_role` but this way is easier,
    # to update existing roles. Could add logic to skip if the tags are up to date
    response = clients.iam_client.tag_role(
        RoleName=role_name,
        Tags=get_tags_for_cost_tracking(principal_id, role_owner=role_owner),
    )

    if existing_role:
        try:
            existing_role_policy = clients.iam_client.get_role_policy(
                RoleName=role_name, PolicyName=role_policy_name
            )["PolicyDocument"]
        except clients.iam_client.exceptions.NoSuchEntityException as e:
            existing_role_policy = None

    if not existing_role or role_policy != existing_role_policy:
        try:
            clients.iam_client.put_role_policy(
                RoleName=role_name,
                PolicyName=role_policy_name,
                PolicyDocument=json.dumps(role_policy),
            )
            return role_arn
        except ClientError as e:
            logger.error(
                f"Failed to put IAM policy for role '{role_name}': {e.response['Error']['Message']}"
            )
            raise
    else:
        logger.debug("Role inline policy is already up to date")

    return role_arn


def get_tags_for_cost_tracking(
    principal_id: str, role_owner: str = "", format: str = "standard"
):
    """
    Generate AWS resource tags that support cost tracking by including the user ID.

    Args:
        principal_id (str): The user or client's unique Gen3 ID
        role_owner (str): A name for the entity using the associated IAM role, if relevant
        format (str):
            One of ["standard" (default), "lowercase", "pascalcase"].
            Different AWS clients/resources expect different tag formats
    """
    tags = [
        {
            "Key": "Name",
            "Value": get_safe_name_from_hostname(principal_id=principal_id),
        },
        {
            "Key": "principal_id",
            "Value": principal_id,
        },
        {
            "Key": "hostname",
            "Value": config["HOSTNAME"],
        },
        {
            "Key": "gen3_service",
            "Value": "gen3-workflow",
        },
    ]
    if role_owner:
        tags.append(
            {
                "Key": "actor",
                "Value": role_owner,
            }
        )
    if format == "pascalcase":
        tags = [{"TagKey": tag["Key"], "TagValue": tag["Value"]} for tag in tags]
    elif format == "lowercase":
        tags = [{"key": tag["Key"], "value": tag["Value"]} for tag in tags]
    return tags
