# Installation

This package uses the [poetry](https://python-poetry.org/)
packaging helper, and can be installed either using pip

    pip install 'certified[all]'

or poetry

    poetry install --all-extras


## Command-Line Interface

Two commands are installed with certified,
a main interface to certificate management
and microservice startup,

```
% certified --help
                                                                      
 Usage: certified [OPTIONS] COMMAND [ARGS]...                         
                                                                      
╭─ Options ──────────────────────────────────────────────────────────╮
│ --help                        Show this message and exit.          │
╰────────────────────────────────────────────────────────────────────╯
╭─ Commands ─────────────────────────────────────────────────────────╮
│ add-client    Add the client directly to your `known_clients`      │
│               list.                                                │
│ add-intro     Add an introduction to use when authenticating to    │
│               servers that trust this signer.                      │
│ add-service   Add the service directly to your `known_servers`     │
│               list.                                                │
│ get-ident     Create a json copy of my certificate suitable for    │
│               sending to a signing authority.                      │
│ get-signer    Create a json copy of my signing certificate.        │
│ init          Create a new signing and end-entity ID.              │
│ introduce     Write an introduction for the subject named by the   │
│               certificate above.  Do not use this function unless  │
│               you have checked both of the following:              │
│ serve         Run the web server with HTTPS certificate-based      │
│               trust setup.                                         │
╰────────────────────────────────────────────────────────────────────╯
```

and a client interface,

```
% message --help
                                                                      
 Usage: message [OPTIONS] URL [DATA]                                  
                                                                      
 Send a json-message to an mTLS-authenticated HTTPS-REST-API.         
                                                                      
╭─ Arguments ────────────────────────────────────────────────────────╮
│ *    url      TEXT  Service's Resource URL [default: None]         │
│                     [required]                                     │
╰────────────────────────────────────────────────────────────────────╯
╭─ json-formatted message body ──────────────────────────────────────╮
│   data      [DATA]  If present, the message is POST-ed to the URL. │
│                     Example: '{"refs": [1,2], "query": "What's the │
│                     weather?"}'                                    │
│                     [default: None]                                │
╰────────────────────────────────────────────────────────────────────╯
╭─ Options ──────────────────────────────────────────────────────────╮
│                     -X       [GET|POST|PUT|DEL  HTTP method to     │
│                              ETE|PATCH]         use.               │
│                                                 [default: None]    │
│                     -v                          show info-level    │
│                                                 logs               │
│                     -vv                         show debug-level   │
│                                                 logs               │
│ --config                     PATH               Config file path   │
│                                                 [default           │
│                                                 $VIRTUAL_ENV/etc/… │
│                                                 [default: None]    │
│ --help                                          Show this message  │
│                                                 and exit.          │
╰────────────────────────────────────────────────────────────────────╯
╭─ headers to pass ──────────────────────────────────────────────────╮
│   -H      TEXT  Interpreted as curl interprets them (split once on │
│                 ": "). Example: -H "X-Token: ABC" gets parsed as   │
│                 headers = {"X-Token": "ABC"}.                      │
╰────────────────────────────────────────────────────────────────────╯
```
