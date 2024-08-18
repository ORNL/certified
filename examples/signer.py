from fastapi import FastAPI, Request

app = FastAPI()

@app.get("/info")
async def getTransportInfo(request: Request):
    transport = request.scope["transport"]
    info = dict([ (k, transport.get_extra_info(k))
                  for k in [ "peername", "sockname",
                             "compression", "cipher", "peercert"]
                ])
    return info
