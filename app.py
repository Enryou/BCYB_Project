# app.py
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from database import SessionLocal, Message
from pydantic import BaseModel
from typing import List
import datetime

# Create an instance of FastAPI
app = FastAPI()

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Define the Pydantic model for message data
class MessageCreate(BaseModel):
    sender_id: str
    recipient_id: str
    encrypted_message: str
    timestamp: datetime.datetime

# Define the POST endpoint to store messages
@app.post("/messages/")
async def store_message(message: MessageCreate, db: Session = Depends(get_db)):
    """
    Store an encrypted message for a recipient.
    Saves the message in the SQLite database.
    """
    db_message = Message(
        sender_id=message.sender_id,
        recipient_id=message.recipient_id,
        encrypted_message=message.encrypted_message,
        timestamp=message.timestamp
    )
    db.add(db_message)
    db.commit()
    db.refresh(db_message)
    return {"message": "Message stored successfully"}

# Define the GET endpoint to retrieve messages for a recipient
@app.get("/messages/{recipient_id}", response_model=List[MessageCreate])
async def get_messages(recipient_id: str, db: Session = Depends(get_db)):
    """
    Retrieve all messages for a specific recipient.
    Fetches messages from the SQLite database. If no messages are found, an HTTP 404 response is returned to indicate that no messages were found for the given recipient.
    """
    messages = db.query(Message).filter(Message.recipient_id == recipient_id).all()
    if not messages:
        raise HTTPException(status_code=404, detail="No messages found for the recipient.")
    return messages
    """
    Retrieve all messages for a specific recipient.
    This function simulates fetching messages from a database (to be implemented later).

    Parameters:
    - recipient_id: The ID of the recipient for whom messages are being retrieved.

    Returns:
    - A list of messages addressed to the recipient.
    """

    # Placeholder for database retrieval logic
    messages = []  # This should be replaced by actual database calls
    print(f"Retrieving messages for recipient: {recipient_id}")
    return messages

# Notes:
# - The POST endpoint (`/messages/`) is intended for storing encrypted messages when the recipient is offline.
# - The GET endpoint (`/messages/{recipient_id}`) is used to retrieve messages for a recipient when they come online.
# - Future steps will include integrating SQLite for persistent storage of these messages, replacing the placeholder logic.
# - All code is written with readability and documentation in mind, making it easy to understand the purpose and flow of each function.
# - No lambda functions are used, and each function is explicitly defined for clarity and ease of documentation.


