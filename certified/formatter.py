# Adapted from https://stackoverflow.com/questions/70891687/how-do-i-get-my-fastapi-applications-console-log-in-json-format-with-a-differen
"""
Note [Loki Example Grafana Dashboard](https://play.grafana.org/d/T512JVH7z/)
uses:
{"msec": "1726452205.703", "connection": "62289830", "connection_requests": "1", "pid": "24", "request_id": "5e4d3b57b3a1ae5ffc7d866a1c76ea11", "request_length": "547", "remote_addr": "85.208.96.255", "remote_user": "", "remote_port": "", "time_local": "16/Sep/2024:02:03:25 +0000", "time_iso8601": "2024-09-16T02:03:25+00:00", "request": "GET /a/984333253/alternative-to-collect-for-amiibo.html HTTP/1.1", "request_uri": "/a/984333253/alternative-to-collect-for-amiibo.html", "args": "", "status": "200", "body_bytes_sent": "11465", "bytes_sent": "11644", "http_referer": "", "http_user_agent": "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)", "http_x_forwarded_for": "85.208.96.255", "http_host": "nl.appfelstrudel.com", "server_name": "ns565366.ip-54-39-133.net", "request_time": "0.092", "upstream": "172.19.0.255:3006", "upstream_connect_time": "0.000", "upstream_header_time": "0.092", "upstream_response_time": "0.092", "upstream_response_length": "72629", "upstream_cache_status": "MISS", "ssl_protocol": "", "ssl_cipher": "", "scheme": "http", "request_method": "GET", "server_protocol": "HTTP/1.1", "pipe": ".", "gzip_ratio": "6.34", "http_cf_ray": "8c3d47ac38620849-IAD","geoip_country_code": "CY"}

"""
from typing import Dict, Union
import json, logging
import time
from http import HTTPStatus
import logging

def get_app_log(record : logging.LogRecord) -> Dict[str,Union[str,int,float]]:
    """
    { "name": "__main__",
      "pid": 1234,
      "uptime": 122.21,
      "level": "INFO",
      "type": "app",
      "timestamp": "2022-01-28 10:46:01,904",
      "module": "app",
      "function": "get_app_log",
      "line": 33,
      "message": "Server started listening on port: 8000"
    }
    """
    return {
            'name': record.name,
            'pid': record.process or -1,
            'uptime': record.relativeCreated*1e-3,
            #'threadId': record.thread,
            'level': record.levelname,
            'type': 'app',
            'timestamp': record.asctime,
            #'filename': record.filename,
            #'pathname': record.pathname,
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'message': record.message,
        }

def get_access_log(record):
    """
    { "name": "__main__",
      "pid": 4121,
      "uptime": 122.21,
      "level": "INFO",
      "type": "access",
      "timestamp": "2022-01-28 10:46:03,587",
      "message": "GET /foo",
      "url": "/foo",
      "host": "127.0.0.1:8000",
      "user-agent": "Mozilla/5.0 ...",
      "accept": "text/html,..."
      "method": "GET",
      "httpVersion": "1.1",
      "statusCode": 200,
      "status": "OK",
      "process_time": 0.001,
    }
    """
    json_obj = get_app_log(record)
    json_obj = {
        'name': record.name,
        'pid': record.process,
        'uptime': record.relativeCreated*1e-3,
        'level': record.levelname,
        'type': 'access',
        'timestamp': record.asctime,
        'message': record.message,
    }
    json_obj.update(record.extra_info)

    return json_obj

class RichFormatter(logging.Formatter):
    def __init__(self, formatter, indent=None):
        logging.Formatter.__init__(self, formatter)
        self.indent = indent

    def format(self, record):
        logging.Formatter.format(self, record)
        if not hasattr(record, 'extra_info'):
            return json.dumps(get_app_log(record), indent=self.indent)
        else:
            return json.dumps(get_access_log(record), indent=self.indent)

try:
    from fastapi import Request, Response
    #from starlette.background import BackgroundTask
    #   response.background = BackgroundTask(write_log_data, request, response,
    #                                        process_time)

    status_reasons = {x.value:x.name for x in list(HTTPStatus)}
    _logger = logging.getLogger("certified.access")

    def rich_log_data(request: Request,
                      response : Response,
                      process_time: float) -> None:
        transport = request.scope.get("transport", None)
        attrs = {}
        cipher = ''

        if transport:
            u = transport.get_extra_info("cipher")
            if u:
                cipher = ' '.join(map(str,u))
            cert = transport.get_extra_info("peercert")
            if cert and "subject" in cert:
                for x in cert["subject"]:
                    attrs.update(dict(x))

        if request.client:
            remote_addr = request.client.host
            remote_port = request.client.port
        else:
            remote_addr = ''
            remote_port = -1
        _logger.info(request.method + ' ' + request.url.path,
                    extra={'extra_info': {
                'ssl_cipher': cipher,
                'remote_user': attrs, # attrs.get("commonName", "")
                'path': request.url.path,
                'query': request.url.query,
                #'query': request.query_params, # multi-dict
                #'path_params': request.path_params, # multi-dict
                'fragment': request.url.fragment,
                'port': request.url.port,
                'host': request.headers['host'],
                'remote_addr': remote_addr,
                'remote_port': remote_port,
                'user-agent': request.headers['user-agent'],
                'accept': request.headers['accept'],
                'method': request.method,
                'httpVersion': request.scope['http_version'],
                'statusCode': response.status_code,
                'status': status_reasons.get(response.status_code),
                'process_time': process_time,
                #'body_bytes_sent': len(response.content),
            }})

    # a middleware to log request/response info
    async def log_request(request: Request, call_next):
        start_time = time.perf_counter()
        response = await call_next(request)
        process_time = time.perf_counter() - start_time
        rich_log_data(request, response, process_time)
        return response
except ImportError:
    pass
