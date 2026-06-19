from typing import List, Optional
from pydantic import BaseModel, ConfigDict, SecretStr

class TrustedClient(BaseModel):
    """Defines a known client."""
    model_config = ConfigDict(extra='ignore')

    cert : str # client b64-der certificate

class TrustedService(BaseModel):
    """
    Defines a service provider.  Used by clients to determine
    how to connect with the service.

    Use the biscuit layer (`Baker`, `BiscuitAuthz`, `Critic`) for
    authorisation — not this record.
    """
    model_config = ConfigDict(extra='ignore')

    url   : str # server location
    cert  : Optional[str] = None # server b64-der certificate (or CA)
    auths : List[str] = [] # names of validators recognized by this service

class LokiConfig(BaseModel):
    url    : str # loki server location
    user   : str # username to connect with
    passwd : SecretStr # password to send
