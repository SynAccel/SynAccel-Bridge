from fastapi import FastAPI, Depends, Header, HTTPException
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from dotenv import load_dotenv
import os

# ---------- Load environment variables ----------
load_dotenv()
API_KEY = os.getenv("API_KEY")

# ---------- Create app ----------
app = FastAPI(title="SynAccel-Bridge API", version="0.1")

# ---------- Security setup ----------
api_key_header = APIKeyHeader(name="Authorization", auto_error=False)

async def verify_api_key(api_key: str = Depends(api_key_header)):
    if api_key != f"Bearer {API_KEY}":
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

# ---------- Confirm message ----------
@app.get("/")
def index():
    return {"message": "SynAccel-Bridge API is running"}

# Define what a valid event looks like
class Event(BaseModel):
    source: str
    type: str
    details: dict

@app.post("/api/event")
async def receive_event(event: Event, auth=Depends(verify_api_key)):
    """Receive and process a security or sensor event."""
    # FastAPI automatically gives you a validated Event object
    return {
        "received": True,
        "data": event.dict()  # Convert the Pydantic object back into a Python dictionary
    }
