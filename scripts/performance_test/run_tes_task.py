from dateutil import parser
import json
import os
import requests
import sys
import time

# ROOT = "https://brhstaging.data-commons.org"
ROOT = "https://pauline.planx-pla.net"
VERBOSE = True


# body = {
#     "name": "Hello-World",
#     "executors": [{"image": "quay.io/nextflow/bash", "command": ["echo hello world!"]}],
# }


def log(msg):
    if not VERBOSE:
        return
    print(msg)


def create_task(body):
    response = requests.post(
        f"{ROOT}/workflows/ga4gh/tes/v1/tasks",
        json=body,
        headers={"authorization": f"bearer {os.environ['GEN3_TOKEN']}"},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    return data["id"]


def monitor_task(task_id):
    max_i = 60  # wait up to 5 min
    status = None
    data = {}
    for i in range(max_i):
        response = requests.get(
            f"{ROOT}/workflows/ga4gh/tes/v1/tasks/{task_id}?view=FULL",
            headers={"authorization": f"bearer {os.environ['GEN3_TOKEN']}"},
        )
        assert response.status_code == 200, response.text
        data = response.json()
        status = data["state"]
        log(f"Task status: {status}")
        if status == "COMPLETE":
            log("Task complete!")
            break
        if status in ["SYSTEM_ERROR", "EXECUTOR_ERROR"]:
            log("Task failed")
            break
        if i == max_i - 1:
            log("Task did not complete in time")
            break
        time.sleep(5)
    return status, data


def main(body):
    task_id = create_task(body)
    status, task_data = monitor_task(task_id)
    if status == "COMPLETE":
        start_time = task_data.get("logs", [{}])[0].get("start_time")
        end_time = task_data.get("logs", [{}])[0].get("end_time")
        duration = parser.parse(end_time) - parser.parse(start_time)
        total_seconds = int(duration.total_seconds())
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        print(f"Runtime: {hours}h {minutes}m {seconds}s")
    else:
        print(json.dumps(task_data, indent=2))
        raise Exception("Task did not complete")


if __name__ == "__main__":
    try:
        assert len(sys.argv) == 2, "Incorrect number of arguments"
        main(json.loads(sys.argv[1]))
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
