from typing import Dict, Any, Annotated

from fastapi import FastAPI, Request, Depends, HTTPException

app = FastAPI()

async def get_user_info(request: Request) -> Dict[str,Any]:
    transport = request.scope["transport"]
    info = dict([ (k, transport.get_extra_info(k))
                  for k in [ "peername", "sockname",
                             "compression", "cipher", "peercert"]
                ])
    return info

# {"peername":["127.0.0.1",37460],"sockname":["127.0.0.1",4433],"compression":null,"cipher":["TLS_AES_256_GCM_SHA384","TLSv1.3",256],"peercert":{"subject":[[["commonName","Charles T. User"]]],"issuer":[[["commonName","Charles T. User"]],[["pseudonym","Signing Certificate"]]],"version":3,"serialNumber":"NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN","notBefore":"Sep 12 05:48:44 2024 GMT","notAfter":"Sep 12 05:48:44 2025 GMT","subjectAltName":[["email","hello@localhost"],["DNS","localhost"],["IP Address","127.0.0.1"]]}}


UserInfo = Annotated[Dict[str,Any], Depends(get_user_info)]

@app.get("/info")
async def getTransportInfo(user_info: UserInfo):
    return user_info
