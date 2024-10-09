""" This helper configures the uvicorn access and error
    logs to send data to a loki server specified by a LokiConfig file.

    Usually, this is a URL like https://logs_xyz.grafana.net/loki/api/v1/push
    with user and passwd provided by an API token.
"""
from typing import Optional, Union
import logging
import logging.handlers
import os
import sys
from multiprocessing import Queue

from logging_loki import LokiHandler, LokiQueueHandler # type: ignore[import-untyped]

from .formatter import RichFormatter
from .models import LokiConfig

Pstr = Union[str, "os.PathLike[str]"]

log_queue : Queue = Queue(-1)

def get_loki_handler(app_name : str, cfgfile : Pstr) -> LokiHandler:
    """ Sets up loki as an additional backend to handler.
    """
    with open(cfgfile, "r", encoding="utf-8") as f:
        config = LokiConfig.model_validate_json(f.read())

    #loki_handler = LokiQueueHandler(
    #    Queue(-1),
    #    url = config.url,
    #    auth = (config.user, config.passwd.get_secret_value()),
    #    tags = {"application": app_name},
    #    version = "1",
    #)
    return LokiHandler(
        url = config.url,
        auth = (config.user, config.passwd.get_secret_value()),
        tags = {"application": app_name},
        version="1",
    )

def _start_listener(app_name:str, cfgfile:Optional[Pstr]=None)->None:
    stream_handler = logging.StreamHandler(sys.stdout)
    if cfgfile is None:
        listener = logging.handlers.QueueListener(log_queue,
                                                  stream_handler)
    else:
        loki_handler = get_loki_handler(app_name, cfgfile)
        listener = logging.handlers.QueueListener(log_queue,
                                                  loki_handler,
                                                  stream_handler)
        #logger.info("Logging to %s", config.url)
    listener.start()

def capture_logs(app_name: str,
                 cfgfile: Optional[Pstr] = None,
                 formatter=None) -> None:
    """ Setup all uvicorn and application logs to
    go to log_queue.
    """
    logger = logging.getLogger(__name__)

    handler = logging.handlers.QueueHandler(log_queue)
    if formatter is None:
        formatter = RichFormatter('%(asctime)s')
    handler.setFormatter(formatter)

    logging.getLogger("certified.access").setLevel(logging.INFO)

    # Send all these loggers to the queue handler
    logger.addHandler(handler) # application's handler
    logging.getLogger("certified.access").addHandler(handler)
    #logging.getLogger("uvicorn.access").addHandler(handler)
    #logging.getLogger("uvicorn.error").addHandler(handler)

    _start_listener(app_name, cfgfile)
