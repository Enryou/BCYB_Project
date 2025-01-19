from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from database_manager import get_user, create_user, create_message, get_messages, get_public_key
import logging

# Initialize FastAPI app
app = FastAPI()

# Define request models using Pydantic
class UserRequest(BaseModel):
    username: str
    password: str
    public_key: str

class LoginRequest(BaseModel):
    username: str
    password: str

class MessageRequest(BaseModel):
    sender: str
    recipient: str
    message: str
    signature: str

@app.post("/register/")
async def register(request: UserRequest):
    """
    Register a new user.
    """
    logging.info(f"Register request: {request}")
    if get_user(request.username):
        raise HTTPException(status_code=400, detail="Username already exists")
    create_user(request.username, request.password, request.public_key)
    return {"message": "User registered successfully"}

@app.post("/login/")
async def login(request: LoginRequest):
    """
    Log in an existing user.
    """
    logging.info(f"Login request: {request}")
    user = get_user(request.username)
    if not user or not user.verify_password(request.password):
        raise HTTPException(status_code=400, detail="Invalid username or password")
    return {"message": "Login successful"}

@app.get("/public_key/{username}/")
async def get_public_key(username: str):
    """
    Retrieve the public key of a user.
    """
    user = get_user(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"public_key": user.public_key}

@app.post("/send_message/")
async def send_message(request: MessageRequest):
    """
    Send a message from one user to another.
    """
    if not get_user(request.sender) or not get_user(request.recipient):
        raise HTTPException(status_code=400, detail="Invalid sender or recipient")
    create_message(request.sender, request.recipient, request.message, request.signature)
    return {"message": "Message sent successfully"}

@app.get("/messages/{recipient}/")
async def get_user_messages(recipient: str):
    """
    Retrieve messages for a specific user.
    """
    messages = get_messages(recipient)
    return [{"sender": msg.sender, "message": msg.message, "signature": msg.signature, "timestamp": msg.timestamp} for msg in messages]