import requests
import os
import json
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
import getpass
from password_validator import PasswordValidator
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

# Base URL for the server
BASE_URL = "http://127.0.0.1:8000"

# Global variables to store login state and user data
login_state = False
current_user = None
current_password = None
current_secret_key = None

# Helper functions
def get_user_dir(username):
    return os.path.join(os.getcwd(), username)

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Encryption and decryption functions
def encrypt_key_with_password(secret_key, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)
    encrypted_secret_key = fernet.encrypt(secret_key)
    return base64.urlsafe_b64encode(salt + encrypted_secret_key).decode()

def decrypt_key_with_password(encrypted_secret_key, password):
    data = base64.urlsafe_b64decode(encrypted_secret_key.encode())
    salt = data[:16]
    encrypted_key = data[16:]
    key = derive_key(password, salt)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_key)

def encrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

def decrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.decrypt(data).decode()

# Key generation and storage functions
def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(private_key, password, username):
    user_dir = get_user_dir(username)
    os.makedirs(user_dir, exist_ok=True)
    encrypted_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )
    with open(os.path.join(user_dir, "private_key.pem"), "wb") as key_file:
        key_file.write(encrypted_private_key)

def load_private_key(password, username):
    user_dir = get_user_dir(username)
    with open(os.path.join(user_dir, "private_key.pem"), "rb") as key_file:
        encrypted_private_key = key_file.read()
    return serialization.load_pem_private_key(encrypted_private_key, password=password.encode())

def save_account_data(username, password, secret_key):
    user_dir = get_user_dir(username)
    os.makedirs(user_dir, exist_ok=True)
    encrypted_secret_key = encrypt_key_with_password(secret_key, password)
    with open(os.path.join(user_dir, "secret.key"), "w") as key_file:
        key_file.write(encrypted_secret_key)

def load_account_data(username, password):
    user_dir = get_user_dir(username)
    with open(os.path.join(user_dir, "secret.key"), "r") as key_file:
        encrypted_secret_key = key_file.read()
    secret_key = decrypt_key_with_password(encrypted_secret_key, password)
    return secret_key

def save_messages_data(chat_partner, messages, username, secret_key):
    """
    Save encrypted messages data to a file.
    """
    user_dir = get_user_dir(username)
    encrypted_data = encrypt_data(json.dumps(messages), secret_key)
    with open(os.path.join(user_dir, f"{chat_partner}_messages.json"), "wb") as data_file:
        data_file.write(encrypted_data)

def load_messages_data(chat_partner, username, secret_key):
    """
    Load and decrypt messages data from a file.
    """
    user_dir = get_user_dir(username)
    file_path = os.path.join(user_dir, f"{chat_partner}_messages.json")
    if not os.path.exists(file_path):
        return []
    with open(file_path, "rb") as data_file:
        encrypted_data = data_file.read()
    decrypted_data = decrypt_data(encrypted_data, secret_key)
    return json.loads(decrypted_data)

#
def validate_password(password):
    """
    Validate the password using specific criteria.
    """
    schema = PasswordValidator()
    schema \
        .min(8) \
        .max(100) \
        .has().uppercase() \
        .has().lowercase() \
        .has().digits() \
        .has().no().spaces()
    return schema.validate(password)

def register():
    """
    Register a new user by providing a username and password.
    """
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    if not validate_password(password):
        print("Password must be at least 8 characters long, contain both uppercase and lowercase letters, digits, and no spaces.")
        return
    private_key, public_key = generate_key_pair()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    secret_key = Fernet.generate_key()
    response = requests.post(f"{BASE_URL}/register/", json={"username": username, "password": password, "public_key": public_key_pem})
    if response.status_code == 200:
        save_private_key(private_key, password, username)
        save_account_data(username, password, secret_key)
        print("Registration successful")
    else:
        print(response.json().get("message", "Registration failed"))

def login():
    """
    Log in an existing user by providing a username and password.
    """
    global login_state, current_user, current_password, current_secret_key
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    response = requests.post(f"{BASE_URL}/login/", json={"username": username, "password": password})
    if response.status_code == 200:
        print("Login successful")
        current_user = username
        current_password = password
        current_secret_key = load_account_data(username, password)
        login_state = True
        get_messages()  # Initial message pull request
    else:
        print(response.json().get("message", "Login failed"))


def send_message():
    """
    Send an encrypted message to another user.
    """
    if not login_state:
        print("You must be logged in to send messages.")
        return
    recipient = input("Enter recipient's username: ")
    message = input("Enter your message: ")
    response = requests.get(f"{BASE_URL}/public_key/{recipient}/")
    if response.status_code == 200:
        recipient_public_key_pem = response.json().get("public_key")
        recipient_public_key = serialization.load_pem_public_key(recipient_public_key_pem.encode())
        encrypted_message = recipient_public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        private_key = load_private_key(current_password, current_user)
        signature = private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        response = requests.post(f"{BASE_URL}/send_message/", json={"sender": current_user, "recipient": recipient, "message": encrypted_message.hex(), "signature": signature.hex()})
        if response.status_code == 200:
            print("Message sent successfully")
            timestamp = response.json().get("timestamp")
            if not timestamp:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
            else:
                timestamp = timestamp.split('.')[0]  # Remove microseconds
            messages = load_messages_data(recipient, current_user, current_secret_key)
            messages.append({"sender": current_user, "recipient": recipient, "message": message, "timestamp": timestamp})
            save_messages_data(recipient, messages, current_user, current_secret_key)
        else:
            print(response.json().get("message", "Message sending failed"))
    else:
        print("Failed to retrieve recipient's public key")

def get_messages():
    """
    Retrieve new messages from the server.
    """
    if not login_state:
        print("You must be logged in to get messages.")
        return
    private_key = load_private_key(current_password, current_user)
    response = requests.get(f"{BASE_URL}/messages/{current_user}/")
    messages = response.json()
    for msg in messages:
        chat_partner = msg['sender'] if msg['sender'] != current_user else msg.get('recipient', current_user)
        decrypted_message = private_key.decrypt(
            bytes.fromhex(msg['message']),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()
        sender_public_key_pem = requests.get(f"{BASE_URL}/public_key/{msg['sender']}").json().get("public_key")
        sender_public_key = serialization.load_pem_public_key(sender_public_key_pem.encode())
        try:
            sender_public_key.verify(
                bytes.fromhex(msg['signature']),
                decrypted_message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Signature verified")
        except:
            print("Signature verification failed")
        chat_messages = load_messages_data(chat_partner, current_user, current_secret_key)
        chat_messages.append({"sender": msg['sender'], "recipient": msg.get('recipient', current_user), "message": decrypted_message, "timestamp": msg['timestamp']})
        save_messages_data(chat_partner, chat_messages, current_user, current_secret_key)
        print(f"{msg['timestamp']} - {msg['sender']}: {decrypted_message}")

def view_past_messages():
    """
    View past messages with a specific chat partner.
    """
    chat_partner = input("Enter chat partner's username to view past messages: ")
    messages = load_messages_data(chat_partner, current_user, current_secret_key)
    if not messages:
        print("No past messages found.")
        return
    for msg in messages:
        print(f"{msg['timestamp']} - {msg['sender']}: {msg['message']}")

def logout():
    """
    Log out the current user.
    """
    global login_state, current_user, current_password, current_secret_key
    login_state = False
    current_user = None
    current_password = None
    current_secret_key = None
    print("Logged out successfully")

def login_menu():
    """
    Display the login menu and handle user input.
    """
    while True:
        print("\n1. Register\n2. Login\n3. Exit")
        choice = input("Choose an option: ")
        if choice == "1":
            register()
        elif choice == "2":
            login()
            if login_state:
                user_menu()
        elif choice == "3":
            break
        else:
            print("Invalid choice. Try again.")

def user_menu():
    """
    Display the user menu and handle user input.
    """
    while login_state:
        print("\n1. Send Message\n2. Get Messages\n3. View Past Messages\n4. Logout")
        choice = input("Choose an option: ")
        if choice == "1":
            send_message()
        elif choice == "2":
            get_messages()
        elif choice == "3":
            view_past_messages()
        elif choice == "4":
            logout()
        else:
            print("Invalid choice. Try again.")

def main():
    """
    Main function to start the application.
    """
    login_menu()

if __name__ == "__main__":
    main()