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

UserInfo = Annotated[Dict[str,Any], Depends(get_user_info)]

@app.get("/info")
async def getTransportInfo(user_info: UserInfo):
    return user_info
