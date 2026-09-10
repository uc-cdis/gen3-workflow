import json
from typing import Union
from gen3workflow.config import config


def dict_to_sorted_json_str(obj: dict) -> str:
    """
    Reads a Python dict and returns a JSON string with ordered keys
    Use case: when comparing JSON objects returned by AWS, comparisons are deterministic and less flaky
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


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
        # client IDs (used as the user ID for `client_credentials` tokens) contain uppercase
        # characters, which are not allowed in S3 bucket or k8s service account names
        user_id = user_id.lower()
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
