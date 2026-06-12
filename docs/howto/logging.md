# Rich JSON logging

`certified serve` runs your application through uvicorn, which provides basic
access logs.  To get structured JSON logs that include the client's certificate
common name, response time, and request details, add the `certified` logging
middleware.

## Add the middleware

```python
import logging
_logger = logging.getLogger(__name__)

from fastapi import FastAPI
app = FastAPI()

try:
    from certified.formatter import log_request
    app.middleware("http")(log_request)
except ImportError:
    pass  # certified not installed, skip rich logging
```

The `try/except` keeps the application importable without `certified` installed
(useful for local development without mTLS).

## Forward logs to Loki

Pass a Loki config file when starting the server:

```bash
certified serve --loki loki.json my_api.server:app
```

`loki.json`:
```json
{
  "url":    "https://logs-prod-00x.grafana.net/loki/api/v1/push",
  "user":   "1111",
  "passwd": "long-b64-password"
}
```

The `url`, `user`, and `passwd` fields correspond to the
[`LokiConfig`](../reference/models.md#lokiconfig) model.

## What gets logged

Each request produces a structured JSON log entry containing:

- Client certificate common name / UID
- Remote address
- HTTP method and path
- Response status code
- Response time

For more on Loki setup see the
[Grafana Loki documentation](https://grafana.com/docs/loki/latest/setup/).
