"""
Tests for the OpenTelemetry tracing and Pyroscope profiling wiring.

Both are off in the test config, so each test builds its own app with the setting it needs
rather than using the session-scoped `client` fixture. The tracer provider, the library
instrumentations and the Pyroscope agent are all process-wide: the provider is installed once
for the module, and the fixtures below undo the rest so nothing leaks into the other modules.
"""

from unittest.mock import MagicMock, patch

from fastapi import FastAPI
import httpx
from opentelemetry import trace
from opentelemetry.instrumentation.botocore import BotocoreInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.instrumentation.logging import LoggingInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind
import pytest

from cdispyutils.observability import continuous_profiling
from cdispyutils.observability.continuous_profiling import (
    profiling_active,
    stop_profiling,
)
from cdispyutils.observability.tracing import reset_tracing_state
from gen3workflow.app import get_app
from gen3workflow.config import config

SERVICE_INFO_PATH = "/ga4gh/tes/v1/service-info"
PYROSCOPE_ADDRESS = "http://test-pyroscope-server:4040"


def build_app() -> FastAPI:
    """
    Build an app whose outbound calls are answered locally.

    Returns:
        FastAPI: a new app, configured from the current `config` values.
    """

    async def handle_request(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"name": "test-tes-server"})

    transport = httpx.MockTransport(handle_request)
    app = get_app(httpx_client=httpx.AsyncClient(transport=transport))
    app.arborist_client.client_cls = lambda: httpx.AsyncClient(transport=transport)
    return app


def app_client(app: FastAPI) -> httpx.AsyncClient:
    """
    Build a client that sends requests to the given app.

    Args:
        app (FastAPI): the app to send to.

    Returns:
        httpx.AsyncClient: an unopened client; use it as an async context manager.
    """
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test-gen3-wf"
    )


def server_spans(exporter: InMemorySpanExporter) -> list:
    """
    Pull the request spans out of an exporter.

    Args:
        exporter (InMemorySpanExporter): the exporter to read.

    Returns:
        list: the finished spans of kind SERVER. The client spans alongside them come from the
            test's own HTTPX client, which the global HTTPX instrumentation also wraps.
    """
    return [
        span for span in exporter.get_finished_spans() if span.kind == SpanKind.SERVER
    ]


@pytest.fixture(scope="module")
def span_exporter():
    """
    Install a tracer provider for this module and hand back the exporter holding its spans.

    `trace.set_tracer_provider` keeps the first provider it is given and only warns on any
    later call, so this is installed before the first `configure_tracing` runs. That call then
    finds a provider already in place and instruments the app against this one.
    """
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    yield exporter


@pytest.fixture(scope="function")
def tracing_enabled():
    """
    Turn tracing on, and undo the process-wide instrumentation afterwards.

    The library instrumentations patch HTTPX, botocore and the logging module globally, so
    leaving them on would have every later test in the session emitting spans.
    """
    original_val = config["ENABLE_TRACING"]
    config["ENABLE_TRACING"] = True
    yield
    config["ENABLE_TRACING"] = original_val
    HTTPXClientInstrumentor().uninstrument()
    BotocoreInstrumentor().uninstrument()
    LoggingInstrumentor().uninstrument()
    reset_tracing_state()


@pytest.fixture(scope="function")
def fake_pyroscope():
    """
    Replace the Pyroscope SDK, and stop the agent afterwards.

    `stop_profiling` runs while the patch is still in place, so the SDK the library calls
    `shutdown` on is this fake and the next test starts with no agent running.
    """
    fake = MagicMock()
    with patch.object(continuous_profiling, "pyroscope", fake):
        yield fake
        stop_profiling()


@pytest.fixture(scope="function")
def profiling_enabled():
    """
    Turn continuous profiling on and point it at an address that is never contacted.
    """
    original_enabled = config["ENABLE_CONTINUOUS_PROFILING"]
    original_address = config["PYROSCOPE_SERVER_ADDRESS"]
    config["ENABLE_CONTINUOUS_PROFILING"] = True
    config["PYROSCOPE_SERVER_ADDRESS"] = PYROSCOPE_ADDRESS
    yield
    config["ENABLE_CONTINUOUS_PROFILING"] = original_enabled
    config["PYROSCOPE_SERVER_ADDRESS"] = original_address


@pytest.mark.asyncio
async def test_tracing_is_off_by_default():
    """
    With `ENABLE_TRACING` off, the app is left uninstrumented, so no request pays for tracing
    it is not configured to send anywhere.
    """
    app = build_app()
    assert not getattr(app, "_is_instrumented_by_opentelemetry", False)


@pytest.mark.asyncio
async def test_request_produces_a_server_span(span_exporter, tracing_enabled):
    """
    With tracing on, a request to a real route produces a request span.
    """
    app = build_app()
    assert getattr(app, "_is_instrumented_by_opentelemetry", False)

    span_exporter.clear()
    async with app_client(app) as client:
        res = await client.get(SERVICE_INFO_PATH)
    assert res.status_code == 200, res.text

    spans = server_spans(span_exporter)
    assert len(spans) == 1
    assert spans[0].attributes["http.route"] == SERVICE_INFO_PATH


@pytest.mark.asyncio
async def test_probe_endpoint_produces_no_span(span_exporter, tracing_enabled):
    """
    The endpoints Kubernetes polls are excluded, so probe traffic does not swamp real traffic
    in the trace backend.
    """
    app = build_app()

    span_exporter.clear()
    async with app_client(app) as client:
        res = await client.get("/_status")
        assert res.status_code == 200
        assert server_spans(span_exporter) == []

        # the same app does emit one for a route that is not excluded
        await client.get(SERVICE_INFO_PATH)

    assert len(server_spans(span_exporter)) == 1


@pytest.fixture(scope="function")
def memory_profiling_enabled():
    """
    Turn memory profiling on.
    """
    original_val = config["PROFILE_MEMORY"]
    config["PROFILE_MEMORY"] = True
    yield
    config["PROFILE_MEMORY"] = original_val


@pytest.fixture(scope="function")
def cpu_profiling_disabled():
    """
    Turn CPU profiling off.
    """
    original_val = config["PROFILE_CPU"]
    config["PROFILE_CPU"] = False
    yield
    config["PROFILE_CPU"] = original_val


@pytest.mark.asyncio
async def test_profiling_is_off_by_default(fake_pyroscope):
    """
    With `ENABLE_CONTINUOUS_PROFILING` off, no agent starts.
    """
    build_app()

    fake_pyroscope.configure.assert_not_called()
    assert not profiling_active()


@pytest.mark.asyncio
async def test_profiling_starts_the_agent_once(fake_pyroscope, profiling_enabled):
    """
    With profiling on, the agent starts under the service name, and building a second app
    leaves the one already running alone.
    """
    build_app()
    build_app()

    fake_pyroscope.configure.assert_called_once()
    kwargs = fake_pyroscope.configure.call_args.kwargs
    assert kwargs["application_name"] == "gen3-workflow"
    assert kwargs["server_address"] == PYROSCOPE_ADDRESS
    assert profiling_active()


@pytest.mark.asyncio
async def test_profiling_settings_reach_the_agent(
    fake_pyroscope, profiling_enabled, memory_profiling_enabled
):
    """
    What the agent collects, and how often, is what the configuration says: memory profiles are
    only collected when `PROFILE_MEMORY` is on.
    """
    build_app()

    kwargs = fake_pyroscope.configure.call_args.kwargs
    assert kwargs["mem_enabled"] is True
    assert kwargs["cpu_enabled"] == config["PROFILE_CPU"]
    assert kwargs["oncpu"] == config["PROFILE_ON_CPU_ONLY"]
    assert kwargs["sample_rate"] == config["PYROSCOPE_SAMPLE_RATE"]
    assert kwargs["upload_interval"] == config["PYROSCOPE_UPLOAD_INTERVAL"]


@pytest.mark.asyncio
async def test_profiling_settings_ignore_the_environment(
    fake_pyroscope, profiling_enabled, monkeypatch
):
    """
    Every profiling setting is passed explicitly, so the environment variables the profiling
    library falls back to cannot turn memory profiling on behind the configuration's back.
    """
    monkeypatch.setenv("PROFILE_MEMORY", "true")
    build_app()

    assert fake_pyroscope.configure.call_args.kwargs["mem_enabled"] is False


@pytest.mark.asyncio
async def test_profiling_with_nothing_to_collect_is_rejected(
    fake_pyroscope, profiling_enabled, cpu_profiling_disabled
):
    """
    Profiling with neither CPU nor memory profiles is refused at startup, rather than running an
    agent that pushes nothing.
    """
    with pytest.raises(AssertionError, match="PROFILE_CPU"):
        build_app()

    fake_pyroscope.configure.assert_not_called()
