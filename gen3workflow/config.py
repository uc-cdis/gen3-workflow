import os

from gen3config import Config
from jsonschema import validate

from gen3workflow import logger

DEFAULT_CFG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "config-default.yaml"
)

NON_EMPTY_STRING_SCHEMA = {"type": "string", "minLength": 1}


class Gen3WorkflowConfig(Config):
    def __init__(self, *args, **kwargs):
        super(Gen3WorkflowConfig, self).__init__(*args, **kwargs)

    def validate(self) -> None:
        """
        Perform a series of sanity checks on a loaded config.
        """
        logger.info("Validating configuration")
        self.validate_top_level_configs()

    def validate_top_level_configs(self) -> None:
        """
        Validate the configured fields
        """
        schema = {
            "type": "object",
            # Forward compatibility: allow unknown configuration keys ("additionalProperties") so
            # that the app remains functional when using configuration files from newer versions
            "additionalProperties": True,
            "properties": {
                "HOSTNAME": {"type": "string"},
                "APP_DEBUG": {"type": "boolean"},
                "HTTPX_DEBUG": {"type": "boolean"},
                "PROXY_PREFIX": {"type": ["string", "null"]},
                "ARBORIST_URL": {"type": ["string", "null"]},
                "MOCK_AUTH": {"type": "boolean"},
                "USER_BUCKET_CACHE_SECONDS": {"type": "integer", "minimum": 1},
                "USER_BUCKETS_REGION": {"type": "string"},
                "VALID_AUTHZ_AUDIENCE": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "DPOP_ENABLED": {"type": "boolean"},
                "DPOP_REQUIRED": {"type": "boolean"},
                "DPOP_SHARED_SECRET": {"type": ["string", "null"]},
                "DPOP_ALLOWED_ISSUERS": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "DPOP_EXEMPT_CLIENT_IDS": {
                    "type": "array",
                    "items": NON_EMPTY_STRING_SCHEMA,
                },
                "DPOP_EXTERNAL_BASE_URL": {"type": ["string", "null"]},
                "DPOP_PROTECTED_PATHS": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                },
                "S3_UPSTREAM_ENDPOINT": {"type": ["string", "null"]},
                "S3_OBJECTS_EXPIRATION_DAYS": {"type": "integer", "minimum": 1},
                "S3_ENDPOINTS_AWS_ACCESS_KEY_ID": {"type": ["string", "null"]},
                "S3_ENDPOINTS_AWS_SECRET_ACCESS_KEY": {"type": ["string", "null"]},
                "KMS_ENCRYPTION_ENABLED": {"type": "boolean"},
                "ENABLE_S3_FILES": {"type": "boolean"},
                "TASK_IMAGE_WHITELIST": {"type": "array", "items": {"type": "string"}},
                "TES_SERVER_URL": {"type": "string"},
                "ENABLE_PROMETHEUS_METRICS": {"type": "boolean"},
                "PROMETHEUS_MULTIPROC_DIR": {"type": "string"},
                "ENABLE_TRACING": {"type": "boolean"},
                "OTEL_EXPORTER_OTLP_ENDPOINT": {"type": "string"},
                "OTEL_EXPORTER_OTLP_PROTOCOL": {"enum": ["grpc", "http/protobuf"]},
                "ENABLE_CONTINUOUS_PROFILING": {"type": "boolean"},
                "PYROSCOPE_SERVER_ADDRESS": {"type": "string"},
                "PROFILE_CPU": {"type": "boolean"},
                "PROFILE_MEMORY": {"type": "boolean"},
                "PROFILE_ON_CPU_ONLY": {"type": "boolean"},
                "PYROSCOPE_SAMPLE_RATE": {"type": "integer", "minimum": 1},
                "PYROSCOPE_UPLOAD_INTERVAL": {"type": "integer", "minimum": 1},
                "ENABLE_OPTIMIZED_NODE_SCHEDULING": {"type": "boolean"},
                "EKS_CLUSTER_NAME": {"type": "string"},
                "EKS_CLUSTER_REGION": {"type": "string"},
                "WORKER_PODS_NAMESPACE": {"type": "string"},
                "EKS_SECURITY_GROUP_NAMES": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
        }
        validate(instance=self, schema=schema)

        assert bool(self["S3_ENDPOINTS_AWS_ACCESS_KEY_ID"]) == bool(
            self["S3_ENDPOINTS_AWS_SECRET_ACCESS_KEY"]
        ), "Both 'S3_ENDPOINTS_AWS_ACCESS_KEY_ID' and 'S3_ENDPOINTS_AWS_SECRET_ACCESS_KEY' must be configured, or both must be left empty"

        if self["ENABLE_S3_FILES"]:
            assert (
                len(self["EKS_SECURITY_GROUP_NAMES"]) > 0
            ), "EKS_SECURITY_GROUP_NAMES must be configured when ENABLE_S3_FILES is True"

        assert (
            not self["DPOP_REQUIRED"] or self["DPOP_ENABLED"]
        ), "DPOP_ENABLED must be True when DPOP_REQUIRED is True, otherwise no DPoP proof is required at all"

        if self["DPOP_ENABLED"]:
            assert (
                get_dpop_shared_secret()
            ), "A 'DPOP_SHARED_SECRET' must be configured, or provided through the environment, when DPOP_ENABLED is True"

        if self["DPOP_REQUIRED"] and not self["DPOP_EXEMPT_CLIENT_IDS"]:
            logger.warning(
                "DPOP_REQUIRED is True and DPOP_EXEMPT_CLIENT_IDS is empty: clients using the 'client_credentials' flow, such as the Funnel worker pods, cannot present a DPoP proof and will be rejected by the DPoP-protected endpoints"
            )

        assert (
            not self["ENABLE_CONTINUOUS_PROFILING"] or self["PYROSCOPE_SERVER_ADDRESS"]
        ), "A 'PYROSCOPE_SERVER_ADDRESS' must be configured when ENABLE_CONTINUOUS_PROFILING is True"

        assert (
            not self["ENABLE_CONTINUOUS_PROFILING"]
            or self["PROFILE_CPU"]
            or self["PROFILE_MEMORY"]
        ), "'PROFILE_CPU' or 'PROFILE_MEMORY' must be True when ENABLE_CONTINUOUS_PROFILING is True, otherwise the agent runs and pushes nothing"


def get_dpop_allowed_issuers() -> list:
    """
    Get the token issuers allowed to sign DPoP-bound access tokens.

    Defaults to the auth service of the configured hostname, which is where Gen3 serves Fence,
    so that a deployment only has to set this when tokens come from somewhere else.

    Returns:
        list: the allowed issuers
    """
    return config["DPOP_ALLOWED_ISSUERS"] or [f"https://{config['HOSTNAME']}/user"]


def get_dpop_shared_secret() -> str | None:
    """
    Get the secret used to sign and verify the stateless DPoP nonces.

    The environment takes precedence over the configuration file, so that deployments can
    inject the secret without templating it into a config file.

    Returns:
        str | None: the shared secret, or None if it is not set anywhere.
    """
    return os.environ.get("DPOP_SHARED_SECRET") or config["DPOP_SHARED_SECRET"]


config = Gen3WorkflowConfig(DEFAULT_CFG_PATH)
try:
    if os.environ.get("GEN3WORKFLOW_CONFIG_PATH"):
        config.load(config_path=os.environ["GEN3WORKFLOW_CONFIG_PATH"])
    else:
        CONFIG_SEARCH_FOLDERS = [
            "/src",
            "{}/.gen3/gen3-workflow".format(os.path.expanduser("~")),
        ]
        config.load(search_folders=CONFIG_SEARCH_FOLDERS)
except Exception:
    logger.warning("Unable to load config, using default config...", exc_info=True)
    config.load(config_path=DEFAULT_CFG_PATH)
