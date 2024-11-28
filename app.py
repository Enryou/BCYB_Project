# app.py

from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy.orm import Session
from database import get_session, User, Message, database
from pydantic import BaseModel
from typing import List
import datetime
from passlib.hash import bcrypt


# Database connection lifecycle using lifespan event handlers
async def startup():
    # Connect to the database when app starts
    await database.connect()


async def shutdown():
    # Disconnect from the database when app shuts down
    await database.disconnect()


# Create an instance of FastAPI
app = FastAPI(on_startup=[startup], on_shutdown=[shutdown])


# Pydantic models for request validation and data representation
class MessageCreate(BaseModel):
    sender_id: str
    recipient_id: str
    encrypted_message: str
    timestamp: datetime.datetime


class UserRegister(BaseModel):
    username: str
    password: str


# Endpoint to register new users
@app.post("/register/")
async def register_user(user: UserRegister, db: Session = Depends(get_session)):
    # Hash the user's password using bcrypt for secure storage
    hashed_password = bcrypt.hash(user.password)

    # Create a new user entry with the hashed password
    db_user = User(username=user.username, hashed_password=hashed_password)

    # Add the user to the database
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return {"message": "User registered successfully"}


# Endpoint to store messages
@app.post("/messages/")
async def store_message(message: MessageCreate, db: Session = Depends(get_session)):
    """
    Store an encrypted message for a recipient in the database.
    This endpoint is used when a user wants to save a message for someone who is currently offline.

    Parameters:
    - message: A Pydantic model containing details like sender_id, recipient_id, encrypted_message, and timestamp.
    - db: A session to interact with the database.

    Returns:
    - A success message indicating that the message has been stored.
    """
    # Create a new message object using the provided data
    db_message = Message(
        sender_id=message.sender_id,
        recipient_id=message.recipient_id,
        encrypted_message=message.encrypted_message,
        timestamp=message.timestamp
    )
    # Add the message to the database session
    db.add(db_message)
    db.commit()
    db.refresh(db_message)
    # Return a success response
    return {"message": "Message stored successfully"}


# Endpoint to retrieve messages for a specific recipient
@app.get("/messages/{recipient_id}", response_model=List[MessageCreate])
async def get_messages(recipient_id: str, db: Session = Depends(get_session)):
    """
    Retrieve all messages for a specific recipient from the database.
    This endpoint can be used when the recipient comes online and wants to fetch stored messages.

    Parameters:
    - recipient_id: The ID of the recipient for whom messages are being retrieved.
    - db: A session to interact with the database.

    Returns:
    - A list of messages addressed to the recipient.
    """
    messages = db.query(Message).filter(Message.recipient_id == recipient_id).all()
    # If no messages are found, raise a 404 HTTP error
    if not messages:
        raise HTTPException(status_code=404, detail="No messages found for the recipient.")
    return messages

# Notes:
# - The POST endpoint (/messages/) is used to store encrypted messages when the recipient is offline.
# - The GET endpoint (/messages/{recipient_id}) is used to retrieve stored messages when the recipient comes online.
# - Using startup and shutdown event handlers for the database ensures that the connection is managed properly across the application's lifecycle.
