from typing import Dict
from fastapi import FastAPI

app = FastAPI()

@app.get("/echo/{value}")
async def root(value : str) -> Dict[str, str]:
    return {"message": value}

