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

    def validate_top_level_configs(self):
        schema = {
            "type": "object",
            "additionalProperties": True,
            "properties": {
                "HOSTNAME": {"type": "string"},
                "DEBUG": {"type": "boolean"},
                "DOCS_URL_PREFIX": {"type": "string"},
                # aws_utils.list_iam_user_keys should be updated to fetch paginated results if >100
                "MAX_IAM_KEYS_PER_USER": {"type": "integer", "maximum": 100},
                "IAM_KEYS_LIFETIME_DAYS": {"type": "integer"},
                "USER_BUCKETS_REGION": {"type": "string"},
                "ARBORIST_URL": {"type": ["string", "null"]},
                "TES_SERVER_URL": {"type": "string"},
            },
        }
        validate(instance=self, schema=schema)


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
