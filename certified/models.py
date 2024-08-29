from typing import List
from pydantic import BaseModel, SecretStr

class TrustedClient(BaseModel):
    """
    Defines a known client.

    TLS certificates don't carry scopes, so we can't
    really use the scope data here.
    """
    cert   : str # client PEM-certificate
    scopes : List[str] = [] # scopes the server will allow this client to gain

class TrustedService(BaseModel):
    """
    Defines a service provider.  To be used by potential
    clients to determine how to connect with the service.
    
    The scopes attribute here defines the scopes
    to be requested on accessing the server.
    The actual granted scopes depend on the
    server's configuration.
    """
    url    : str # server location
    cert   : str # server PEM-encoded certificate (or CA)
    scopes : List[str] = [] # scopes client should request when using this service
    auths : List[str] = [] # names of validators recognized by this service

class LokiConfig(BaseModel):
    url    : str # loki server location
    user   : str # username to connect with
    passwd : SecretStr # password to send
