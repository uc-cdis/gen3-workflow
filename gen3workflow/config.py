from itertools import chain
# from jsonschema import validate
import os
from sqlalchemy.engine.url import make_url, URL

from gen3config import Config

from . import logger

DEFAULT_CFG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "config-default.yaml"
)

NON_EMPTY_STRING_SCHEMA = {"type": "string", "minLength": 1}


class Gen3WorkflowConfig(Config):
    def __init__(self, *args, **kwargs):
        super(Gen3WorkflowConfig, self).__init__(*args, **kwargs)

    # def post_process(self) -> None:
    #     # generate DB_URL from DB configs or env vars
    #     self["DB_URL"] = make_url(
    #         URL(
    #             drivername=os.environ.get("DB_DRIVER", self["DB_DRIVER"]),
    #             host=os.environ.get("DB_HOST", self["DB_HOST"]),
    #             port=os.environ.get("DB_PORT", self["DB_PORT"]),
    #             username=os.environ.get("DB_USER", self["DB_USER"]),
    #             password=os.environ.get("DB_PASSWORD", self["DB_PASSWORD"]),
    #             database=os.environ.get("DB_DATABASE", self["DB_DATABASE"]),
    #         ),
    #     )

    def validate(self) -> None:
        """
        Perform a series of sanity checks on a loaded config.
        """
        logger.info("Validating configuration")
        # self.validate_redirect_configs()

    # def validate_redirect_configs(self):
    #     """
    #     Example:
    #         REDIRECT_CONFIGS:
    #             my_redirect:
    #                 redirect_url: http://url.com
    #                 params:
    #                     - request_id
    #     """
    #     schema = {
    #         "type": "object",
    #         "patternProperties": {
    #             ".*": {  # unique ID
    #                 "type": "object",
    #                 "additionalProperties": False,
    #                 "required": ["redirect_url"],
    #                 "properties": {
    #                     "redirect_url": NON_EMPTY_STRING_SCHEMA,
    #                     "params": {
    #                         "type": "array",
    #                         "items": {"enum": self.allowed_params_from_db},
    #                     },
    #                 },
    #             }
    #         },
    #     }
    #     validate(instance=self["REDIRECT_CONFIGS"], schema=schema)


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
