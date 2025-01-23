# Peer-to-Peer Encrypted Messaging System

This project is a secure, peer-to-peer encrypted messaging system built with Python. It includes features for user registration, login, message encryption/decryption, and secure key management.

## Features

- **User Authentication**: Registration and login functionalities with password hashing.
- **Public/Private Key Encryption**: RSA keys are generated for each user to encrypt and sign messages.
- **Message Encryption**: Messages are securely encrypted with RSA and stored in a database.
- **Persistent Data**: Encrypted user data and messages are stored locally and on the server.

## Prerequisites
- Only for Linux at the moment
- Python 3.8+
- SQLite (for local database management)

## Installation

### Clone the Repository
```bash
git clone https://github.com/Enryou/BCYB_Project.git
```

### Set Up the Python Environment
1. Create a virtual environment:
   ```bash
   python -m venv venv
   ```
2. Activate the virtual environment:
   ```bash
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Set Up the Database

1. Run the `database_manager.py` script to initialize the SQLite database:
   ```bash
   python database_manager.py
   ```

   This will create a `messages.db` file in the project directory.

### Running the Server

1. Start the server by running:
   ```bash
   uvicorn server_routes:app --reload
   ```

   The server will be accessible at `http://127.0.0.1:8000`.

### Running the Client

1. Run the client application:
   ```bash
   python client.py
   ```

## How It Works

### Registration
- Users register with a username and password.
- A pair of RSA keys (private and public) is generated.
- The private key is encrypted with the user's password and stored locally.
- The public key is uploaded to the server.

### Login
- Users log in with their credentials.
- The private key and secret key are loaded and decrypted locally.

### Sending Messages
- Messages are encrypted using the recipient's public key.
- The message and a digital signature are sent to the server.
- The server stores the encrypted message.

### Receiving Messages
- Messages are retrieved from the server.
- The client decrypts the messages using the user's private key.
- Digital signatures are verified to ensure authenticity.

## Usage

### Client Menu Options

1. **Register**: Register a new user.
2. **Login**: Log in with an existing username and password.
3. **Send Message**: Send an encrypted message to another user.
4. **Get Messages**: Retrieve messages sent to the logged-in user.
5. **View Past Messages**: View decrypted past messages stored locally.
6. **Logout**: Logout from the current session.

### Security Features

- **Password Validation**: Passwords must meet strict complexity requirements.
- **Encryption**: RSA for key encryption and message exchange.
- **Signature Verification**: Ensures message integrity and authenticity.

## File Overview

- `client.py`: Handles user interaction, encryption, and communication with the server.
- `server_routes.py`: Defines API routes for user registration, login, and message exchange.
- `database_manager.py`: Manages the SQLite database and ORM models.
- `requirements.txt`: Lists all the dependencies required for the project.

