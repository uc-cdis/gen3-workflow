import json
from typing import Union
from urllib.parse import urlparse

from botocore.exceptions import ClientError

from gen3workflow import logger
from gen3workflow.aws import clients
from gen3workflow.config import config

OUTPUTS_ARE_READY_CACHE: set[str] = set()


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


def are_outputs_ready(user_id: str, task_id, outputs: list):
    """
    Check if all the files in the provided list of outputs are up to date in the user's bucket.
    Once all the outputs are ready, the result is cached to avoid unnecessary S3 requests.

    Returns:
        tuple (bool, list[str]): whether all outputs are ready, and any detailed logs to return to
            the user
    """
    if task_id in OUTPUTS_ARE_READY_CACHE:
        return True, []

    user_bucket_name = get_bucket_name_from_user_id(user_id)
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
        OUTPUTS_ARE_READY_CACHE.add(task_id)

    return all_ready, logs
