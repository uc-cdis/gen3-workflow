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
            "additionalProperties": False,
            "properties": {
                "HOSTNAME": {"type": "string"},
                "APP_DEBUG": {"type": "boolean"},
                "HTTPX_DEBUG": {"type": "boolean"},
                "DOCS_URL_PREFIX": {"type": "string"},
                "ARBORIST_URL": {"type": ["string", "null"]},
                "MOCK_AUTH": {"type": "boolean"},
                "USER_BUCKETS_REGION": {"type": "string"},
                "S3_OBJECTS_EXPIRATION_DAYS": {"type": "integer", "minimum": 1},
                "S3_ENDPOINTS_AWS_ACCESS_KEY_ID": {"type": ["string", "null"]},
                "S3_ENDPOINTS_AWS_SECRET_ACCESS_KEY": {"type": ["string", "null"]},
                "KMS_ENCRYPTION_ENABLED": {"type": "boolean"},
                "TASK_IMAGE_WHITELIST": {"type": "array", "items": {"type": "string"}},
                "TES_SERVER_URL": {"type": "string"},
                "ENABLE_PROMETHEUS_METRICS": {"type": "boolean"},
                "PROMETHEUS_MULTIPROC_DIR": {"type": "string"},
                "WORKER_PODS_NAMESPACE": {"type": "string"},
                "EKS_CLUSTER_NAME": {"type": "string"},
                "EKS_CLUSTER_REGION": {"type": "string"},
            },
        }
        validate(instance=self, schema=schema)

        assert bool(self["S3_ENDPOINTS_AWS_ACCESS_KEY_ID"]) == bool(
            self["S3_ENDPOINTS_AWS_SECRET_ACCESS_KEY"]
        ), "Both 'S3_ENDPOINTS_AWS_ACCESS_KEY_ID' and 'S3_ENDPOINTS_AWS_SECRET_ACCESS_KEY' must be configured, or both must be left empty"


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
