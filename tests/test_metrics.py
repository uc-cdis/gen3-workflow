"""
Tests for the Prometheus request metrics recorded by the cdispyutils observability middleware.

The `client` fixture is session-scoped and the counters live on the app it built, so by the
time any one test runs they already hold whatever every earlier test recorded. Each test
therefore scrapes before and after and asserts on the difference.

A test that expects a series to grow also has to send the request once before measuring.
`PROMETHEUS_MULTIPROC_DIR` is set, so counter values are stored per process rather than per
registry and are shared by every app the suite builds, while each registry only exposes the
label combinations that app itself has recorded. The first request to a combination therefore
makes it appear at the total every other app already reached, not at one.
"""

from prometheus_client.parser import text_string_to_metric_families
import pytest

from cdispyutils.observability.constants import UNMATCHED_PATH
from gen3workflow.config import config
from tests.conftest import trailing_slash, TEST_USER_TOKEN

REQUEST_COUNTER = "gen3_workflow_api_requests_total"
DURATION_COUNT = "gen3_workflow_api_request_duration_seconds_count"
DURATION_SUM = "gen3_workflow_api_request_duration_seconds_sum"

SERVICE_INFO_PATH = "/ga4gh/tes/v1/service-info"
TASKS_PATH = "/ga4gh/tes/v1/tasks"


async def scrape(client) -> str:
    """
    Read the current metrics exposition from the app.

    Args:
        client (httpx.AsyncClient): the test client.

    Returns:
        str: the exposition text. `/metrics/` is itself exempt from the request metrics, so
            reading them does not change them.
    """
    res = await client.get("/metrics/")
    assert res.status_code == 200
    return res.text


def total(scrape_text: str, sample_name: str, **labels: str) -> float:
    """
    Add up every sample of one metric whose labels include the given ones.

    Args:
        scrape_text (str): exposition text from `scrape`.
        sample_name (str): the sample name, which for a counter carries the `_total` suffix
            and for a histogram the `_count` or `_sum` suffix.
        **labels (str): labels the sample must carry. A sample with extra labels beyond these
            still counts, so leaving `status_code` out totals a path across status codes.

    Returns:
        float: the sum, or 0.0 when nothing matches - which is also what an absent metric
            gives, since a label combination that was never recorded has no series.
    """
    return sum(
        sample.value
        for family in text_string_to_metric_families(scrape_text)
        for sample in family.samples
        if sample.name == sample_name and labels.items() <= sample.labels.items()
    )


@pytest.fixture(scope="function")
def reset_config_dpop_required():
    """
    Reset the `DPOP_REQUIRED` configuration at the end of tests that use this fixture.
    """
    original_val = config["DPOP_REQUIRED"]
    yield
    config["DPOP_REQUIRED"] = original_val


@pytest.mark.asyncio
async def test_request_is_counted_by_method_path_and_status(client):
    """
    A request to a real route increments the counter series for its method, route template and
    status code.
    """
    labels = {"method": "GET", "path": SERVICE_INFO_PATH, "status_code": "200"}
    await client.get(SERVICE_INFO_PATH)
    before = total(await scrape(client), REQUEST_COUNTER, **labels)

    res = await client.get(SERVICE_INFO_PATH)
    assert res.status_code == 200, res.text

    assert total(await scrape(client), REQUEST_COUNTER, **labels) == before + 1


@pytest.mark.asyncio
async def test_path_label_is_the_route_template(client):
    """
    A path parameter is recorded as its route template, so that one series covers every task
    instead of one series per task ID.
    """
    task_id = "metrics-test-task-id"
    await client.get(f"{TASKS_PATH}/{task_id}")
    before = total(
        await scrape(client),
        REQUEST_COUNTER,
        method="GET",
        path=f"{TASKS_PATH}/{{task_id}}",
    )

    await client.get(f"{TASKS_PATH}/{task_id}")

    after_text = await scrape(client)
    assert (
        total(
            after_text, REQUEST_COUNTER, method="GET", path=f"{TASKS_PATH}/{{task_id}}"
        )
        == before + 1
    )
    assert task_id not in after_text


@pytest.mark.asyncio
async def test_request_duration_is_recorded(client):
    """
    The same request that increments the counter also records one observation in the duration
    histogram.
    """
    labels = {"method": "GET", "path": SERVICE_INFO_PATH, "status_code": "200"}
    await client.get(SERVICE_INFO_PATH)
    before_text = await scrape(client)
    before_count = total(before_text, DURATION_COUNT, **labels)
    before_sum = total(before_text, DURATION_SUM, **labels)

    res = await client.get(SERVICE_INFO_PATH)
    assert res.status_code == 200, res.text

    after_text = await scrape(client)
    assert total(after_text, DURATION_COUNT, **labels) == before_count + 1
    assert total(after_text, DURATION_SUM, **labels) > before_sum


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["/_status", "/_version"])
async def test_probe_endpoints_are_not_counted(client, endpoint):
    """
    The endpoints Kubernetes polls are exempt, so probe traffic does not drown out real
    traffic in the counter.
    """
    before = total(await scrape(client), REQUEST_COUNTER)

    res = await client.get(endpoint)
    assert res.status_code == 200

    after_text = await scrape(client)
    assert total(after_text, REQUEST_COUNTER, path=endpoint) == 0
    # nothing was recorded under any other label either, e.g. `<unmatched>`
    assert total(after_text, REQUEST_COUNTER) == before


@pytest.mark.asyncio
async def test_metrics_endpoint_does_not_count_itself(client):
    """
    Scraping the metrics endpoint records nothing, so the scrape interval does not show up as
    application traffic.
    """
    before = total(await scrape(client), REQUEST_COUNTER)

    after_text = await scrape(client)
    assert total(after_text, REQUEST_COUNTER, path="/metrics") == 0
    assert total(after_text, REQUEST_COUNTER, path="/metrics/") == 0
    assert total(after_text, REQUEST_COUNTER) == before


@pytest.mark.asyncio
async def test_request_rejected_by_dpop_is_counted(client, reset_config_dpop_required):
    """
    A request the DPoP middleware rejects is still counted, with the status code it was
    rejected with. This is what registering the metrics middleware after the DPoP one buys:
    the metrics middleware ends up outside it and sees the rejection.

    Its path is `<unmatched>` rather than the route template. Starlette only records the
    matched route once the request reaches the router, which a rejection never does, so no
    middleware outside the router can label one by route.
    """
    config["DPOP_REQUIRED"] = True
    labels = {"method": "POST", "path": UNMATCHED_PATH, "status_code": "401"}
    await client.post(TASKS_PATH, json={"name": "test-task"})
    before = total(await scrape(client), REQUEST_COUNTER, **labels)

    res = await client.post(TASKS_PATH, json={"name": "test-task"})
    assert res.status_code == 401

    assert total(await scrape(client), REQUEST_COUNTER, **labels) == before + 1


@pytest.mark.asyncio
async def test_metrics_endpoint(client, trailing_slash):
    """
    Test hitting the metrics endpoint
    """
    res = await client.get(
        f"/metrics{'/' if trailing_slash else ''}",
        headers={"Authorization": f"bearer {TEST_USER_TOKEN}"},
    )

    # Metrics endpoint is mounted at /metrics/,
    # so when trying to access it without a trailing slash, it should redirect, returning a 307 status code.
    if trailing_slash:
        assert res.status_code == 200
    else:
        assert res.status_code == 307
        assert res.next_request.url == "http://test-gen3-wf/metrics/"
