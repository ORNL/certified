""" This helper configures the uvicorn access and error
    logs to send data to a LOKI_ENDPOINT.

    Usually, this is a URL like https://logs_xyz.grafana.net/loki/api/v1/push
    with user and passwd provided by an API token.
"""
from typing import Optional, Union
import logging
import os
from multiprocessing import Queue
_logger = logging.getLogger(__name__)

from logging_loki import LokiQueueHandler # type: ignore[import-untyped]

from .models import LokiConfig

Pstr = Union[str, os.PathLike[str]]

def configure(app_name : str, cfgfile : Pstr) -> None:
    with open(cfgfile, "r", encoding="utf-8") as f:
        config = LokiConfig.model_validate_json(f.read())

    loki_logs_handler = LokiQueueHandler(
        Queue(-1),
        url = config.url,
        auth = (config.user, config.passwd.get_secret_value()),
        tags = {"application": app_name},
        version = "1",
    )
    #loki_logs_handler.setFormatter(
    #    logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s')
    #)

    _logger.addHandler(loki_logs_handler)
    logging.getLogger("uvicorn.access").addHandler(loki_logs_handler)
    logging.getLogger("uvicorn.error").addHandler(loki_logs_handler)
    _logger.info("Logging to %s", config.url)
