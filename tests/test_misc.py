import pytest

from gen3workflow.aws.aws_utils import (
    _OUTPUTS_ARE_READY_CACHE,
    are_outputs_ready,
    get_safe_name_from_hostname,
)
from gen3workflow.config import config
from tests.conftest import TEST_USER_ID, TEST_USER_TOKEN, s3_put_object


@pytest.fixture(scope="function")
def reset_config_hostname():
    """
    Reset the `HOSTNAME` configuration at the end of tests that use this fixture
    """
    original_val = config["HOSTNAME"]
    yield
    config["HOSTNAME"] = original_val


def test_get_safe_name_from_hostname(reset_config_hostname):
    """
    Test that `get_safe_name_from_hostname` correctly generates "safe names" from hostnames
    """
    user_id = "asdfgh"

    # test a hostname with a `.`; it should be replaced by a `-`
    config["HOSTNAME"] = "qwert.qwert"
    escaped_shortened_hostname = "qwert-qwert"
    safe_name = get_safe_name_from_hostname(user_id)
    assert len(safe_name) < 63
    assert safe_name == f"gen3wf-{escaped_shortened_hostname}-{user_id}"

    # test with a hostname that would result in a name longer than the max (63 chars)
    config["HOSTNAME"] = (
        "qwertqwert.qwertqwert.qwertqwert.qwertqwert.qwertqwert.qwertqwert"
    )
    escaped_shortened_hostname = "qwertqwert-qwertqwert-qwertqwert-qwertqwert-qwert"
    safe_name = get_safe_name_from_hostname(user_id)
    assert len(safe_name) == 63
    assert safe_name == f"gen3wf-{escaped_shortened_hostname}-{user_id}"

    # test with a hostname longer than max and an extra few characters of reserved length
    reserved_length = len("qwert")
    escaped_shortened_hostname_with_reserved_length = (
        "qwertqwert-qwertqwert-qwertqwert-qwertqwert-"
    )
    safe_name = get_safe_name_from_hostname(user_id, reserved_length=reserved_length)
    assert len(safe_name) + reserved_length == 63
    assert (
        safe_name
        == f"gen3wf-{escaped_shortened_hostname_with_reserved_length}-{user_id}"
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
    s3_put_object(bucket=bucket, key="ready", body=file_contents)

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
        {"outputs": outputs, "end_time": "2020-10-02T11:00:00-05:00"},
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
        {"outputs": [ready_file], "end_time": "2020-10-02T11:00:00-05:00"},
    )
    assert (
        ready == False
    ), f"`are_outputs_ready` should have returned ready=False. Logs: {logs}"
    assert logs == [
        f"Output 's3://{bucket}/ready' is not present in the bucket: not ready"
    ]
    assert _OUTPUTS_ARE_READY_CACHE == set()

    # on the 2nd try, `are_outputs_ready` should be looking for the output file again
    ready, logs = are_outputs_ready(
        TEST_USER_ID,
        task_id,
        {"outputs": [ready_file], "end_time": "2020-10-02T11:00:00-05:00"},
    )
    assert (
        ready == False
    ), f"`are_outputs_ready` should have returned ready=False. Logs: {logs}"
    assert logs == [
        f"Output 's3://{bucket}/ready' is not present in the bucket: not ready"
    ]
    assert _OUTPUTS_ARE_READY_CACHE == set()

    # create the expected output file in the bucket
    s3_put_object(bucket=bucket, key="ready", body=file_contents)

    # `are_outputs_ready` should now find the output file and return "ready=True".
    # the task ID should be cached since the outputs are ready.
    ready, logs = are_outputs_ready(
        TEST_USER_ID,
        task_id,
        {"outputs": [ready_file], "end_time": "2020-10-02T11:00:00-05:00"},
    )
    assert (
        ready == True
    ), f"`are_outputs_ready` should have returned ready=True. Logs: {logs}"
    assert logs == [
        f"Output 's3://{bucket}/ready' of expected size {size} is present with size {size}: ready"
    ]
    assert _OUTPUTS_ARE_READY_CACHE == {task_id}

    # on the 2nd try after uploading the output file, `are_outputs_ready` should use the cached
    # result and not look for the output file again (so the returned logs should be empty)
    ready, logs = are_outputs_ready(
        TEST_USER_ID,
        task_id,
        {"outputs": [ready_file], "end_time": "2020-10-02T11:00:00-05:00"},
    )
    assert (
        ready == True
    ), f"`are_outputs_ready` should have returned ready=True. Logs: {logs}"
    assert logs == []
    assert _OUTPUTS_ARE_READY_CACHE == {task_id}
