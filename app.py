# Import FastAPI and other required libraries
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import datetime

# Create an instance of FastAPI
app = FastAPI()


# Define the Pydantic model for message data
# This model ensures that the incoming request follows the expected format
class Message(BaseModel):
    sender_id: str  # ID of the user sending the message
    recipient_id: str  # ID of the recipient of the message
    encrypted_message: str  # The actual message, encrypted
    timestamp: datetime.datetime  # Timestamp of when the message was sent


# Define the POST endpoint to store messages
# This endpoint will be used to save messages when a recipient is offline
@app.post("/messages/")
async def store_message(message: Message):
    """
    Store an encrypted message for a recipient.
    This function simulates saving the message to a database (to be implemented later).

    Parameters:
    - message: A Message object containing sender_id, recipient_id, encrypted_message, and timestamp.

    Returns:
    - A success message indicating that the message has been stored.
    """
    # Placeholder for database storage logic
    print(f"Storing message: {message}")
    return {"message": "Message stored successfully"}


# Define the GET endpoint to retrieve messages for a recipient
# This endpoint will be used when a recipient comes online and wants to retrieve stored messages
@app.get("/messages/{recipient_id}", response_model=List[Message])
async def get_messages(recipient_id: str):
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


