from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="SynAccel-Bridge API", version="0.1")

@app.get("/")
def index():
    return {"message": "SynAccel-Bridge API is running"}

# Define what a valid event looks like
class Event(BaseModel):
    source: str
    type: str
    details: dict

@app.post("/api/event")
async def receive_event(event: Event):
    """Receive and process a security or sensor event."""
    # FastAPI automatically gives you a validated Event object
    return {
        "received": True,
        "data": event.dict()  # Convert the Pydantic object back into a Python dictionary
    }
