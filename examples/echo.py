from typing import Dict, Any
from fastapi import FastAPI, Body

app = FastAPI()

@app.get("/echo/{value}")
async def root(value : str) -> Dict[str, str]:
    return {"message": value}

@app.post("/echo")
async def echo(payload: Any = Body(None)):
    print(payload)
    return payload
