import logging
from logging.handlers import RotatingFileHandler
from configuration import config


# Logging configuration
log = logging.getLogger(__name__)
log.setLevel(getattr(logging, config['logging']['log_level'].upper()))
log_format = logging.Formatter("%(asctime)s {%(pathname)s:%(lineno)d} [%(levelname)s] %(message)s")
if config['logging']['file']:
    # Ensures logs are written to the project folder even if the script is
    # executed from another directory
    log_path = "/".join(__file__.split("/")[:-1])
    log_file = RotatingFileHandler(
        filename=f"{log_path}/application.log",
        maxBytes=10 * 1024 * 1024,  # Bytes to Megabytes
        backupCount=5
        )
    log_file.setFormatter(log_format)
    log.addHandler(log_file)
if config['logging']['console']:
    log_stream = logging.StreamHandler()
    log_stream.setFormatter(log_format)
    log.addHandler(log_stream)
