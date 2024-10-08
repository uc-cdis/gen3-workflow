from cdislogging import get_logger


# Can't read config yet. Just set to debug for now.
# Later, in app.get_app(), will actually set level based on config
logger = get_logger("gen3workflow", log_level="debug")
