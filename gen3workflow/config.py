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

    def post_process(self) -> None:
        # generate DB_CONNECTION_STRING from DB configs or env vars
        drivername = os.environ.get("DB_DRIVER", self["DB_DRIVER"])
        host = os.environ.get("DB_HOST", self["DB_HOST"])
        port = os.environ.get("DB_PORT", self["DB_PORT"])
        username = os.environ.get("DB_USER", self["DB_USER"])
        password = os.environ.get("DB_PASSWORD", self["DB_PASSWORD"])
        database = os.environ.get("DB_DATABASE", self["DB_DATABASE"])
        self["DB_CONNECTION_STRING"] = (
            f"{drivername}://{username}:{password}@{host}:{port}/{database}"
        )

    def validate(self) -> None:
        """
        Perform a series of sanity checks on a loaded config.
        """
        logger.info("Validating configuration")
        self.validate_top_level_configs()

    def validate_top_level_configs(self) -> None:
        schema = {
            "type": "object",
            "additionalProperties": True,
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
                "DB_DRIVER": {"type": "string"},
                "DB_HOST": {"type": "string"},
                "DB_PORT": {"type": "integer"},
                "DB_USER": {"type": "string"},
                "DB_PASSWORD": {"type": "string"},
                "DB_DATABASE": {"type": "string"},
                "DB_CONNECTION_STRING": {"type": "string"},
                "TASK_IMAGE_WHITELIST": {"type": "array", "items": {"type": "string"}},
                "TES_SERVER_URL": {"type": "string"},
                "ENABLE_PROMETHEUS_METRICS": {"type": "boolean", "default": False},
                "PROMETHEUS_MULTIPROC_DIR": {
                    "type": "string",
                    "default": "/var/tmp/prometheus_metrics",
                },
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


if __name__ == "__main__":
    # used by `bin._common_setup.sh` to create the database as configured
    host = os.environ.get("DB_HOST", config["DB_HOST"])
    port = os.environ.get("DB_PORT", config["DB_PORT"])
    username = os.environ.get("DB_USER", config["DB_USER"])
    password = os.environ.get("DB_PASSWORD", config["DB_PASSWORD"])
    database = os.environ.get("DB_DATABASE", config["DB_DATABASE"])
    print("\n", host, port, username, password, database)
