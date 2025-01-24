import logging

import cdislogging
import gunicorn.glogging

# do not overwrite gunicorn's `config`
from gen3workflow.config import config as app_config


class CustomLogger(gunicorn.glogging.Logger):
    """
    Initialize root and gunicorn loggers with cdislogging configuration.
    """

    @staticmethod
    def _remove_handlers(logger):
        """
        Use Python's built-in logging module to remove all handlers associated
        with logger (logging.Logger).
        """
        while logger.handlers:
            logger.removeHandler(logger.handlers[0])

    def __init__(self, cfg):
        """
        Apply cdislogging configuration after gunicorn has set up it's loggers.
        """
        super().__init__(cfg)

        self._remove_handlers(logging.getLogger())

        # httpx uses the log level it sees first when the client is initialized, which is this one
        cdislogging.get_logger(
            None, log_level="debug" if app_config["HTTPX_DEBUG"] else "warn"
        )

        for logger_name in ["gunicorn", "gunicorn.error", "gunicorn.access"]:
            self._remove_handlers(logging.getLogger(logger_name))
            cdislogging.get_logger(
                logger_name,
                log_level="debug" if app_config["APP_DEBUG"] else "info",
            )


logger_class = CustomLogger

wsgi_app = "gen3workflow.app:app"
bind = "0.0.0.0:8000"

workers = 2

# default was `30` for the 2 below
timeout = 90
graceful_timeout = 90
