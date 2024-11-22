# client_app.py

from kivy.app import App  # Import the main App class from Kivy, which serves as the entry point for the application
from kivy.uix.boxlayout import \
    BoxLayout  # BoxLayout is a simple way to organize widgets in a vertical or horizontal box
from kivy.uix.button import Button  # Button widget, used to handle actions when pressed
from kivy.uix.textinput import TextInput  # TextInput widget, used for text entry fields
from kivy.uix.label import Label  # Label widget, used to display text on the screen
import requests  # Requests library is used to make HTTP requests to the FastAPI server
import datetime  # Datetime library is used for generating timestamps for messages

# Define the base URL for the FastAPI server
BASE_URL = "http://127.0.0.1:8000"


# Define the MessengerApp class, inheriting from Kivy's App class
class MessengerApp(App):
    def __init__(self, **kwargs):
        # Call the superclass constructor and pass any keyword arguments
        super(MessengerApp, self).__init__(**kwargs)

        # Initialize attributes here to avoid warnings from PyCharm and ensure all widgets are defined
        self.layout = None
        self.username_input = None
        self.password_input = None
        self.register_button = None
        self.recipient_input = None
        self.message_input = None
        self.send_button = None
        self.feedback_label = None

    def build(self):
        # Create a main layout using a BoxLayout to organize the widgets vertically with padding and spacing
        self.layout = BoxLayout(orientation='vertical', padding=10, spacing=10)

        # Add input fields for user registration (Username and Password)
        self.username_input = TextInput(hint_text="Username", multiline=False)
        self.password_input = TextInput(hint_text="Password", multiline=False, password=True)

        # Add widgets to layout for user registration section
        self.layout.add_widget(Label(text="Register a new user"))  # Label to describe the section
        self.layout.add_widget(self.username_input)  # TextInput for username
        self.layout.add_widget(self.password_input)  # TextInput for password

        # Add a button for registering new users and bind it to the `register_user` method
        self.register_button = Button(text="Register")
        self.register_button.bind(on_press=self.register_user)  # On button press, call the register_user method
        self.layout.add_widget(self.register_button)

        # Add input fields for sending a message (Recipient ID and Encrypted Message)
        self.recipient_input = TextInput(hint_text="Recipient ID", multiline=False)
        self.message_input = TextInput(hint_text="Encrypted Message", multiline=True)

        # Add widgets to layout for the messaging section
        self.layout.add_widget(Label(text="Send a message"))  # Label to describe the section
        self.layout.add_widget(self.recipient_input)  # TextInput for recipient ID
        self.layout.add_widget(self.message_input)  # TextInput for encrypted message

        # Add a button for sending messages and bind it to the `send_message` method
        self.send_button = Button(text="Send Message")
        self.send_button.bind(on_press=self.send_message)  # On button press, call the send_message method
        self.layout.add_widget(self.send_button)

        # Add a label for displaying feedback messages to the user (e.g., success or error messages)
        self.feedback_label = Label(text="")
        self.layout.add_widget(self.feedback_label)

        # Return the complete layout as the root widget of the application
        return self.layout

    # Method for handling user registration
    def register_user(self):
        # Get the username and password from the text input fields
        username = self.username_input.text
        password = self.password_input.text

        # Check if the username or password fields are empty
        if not username or not password:
            self.feedback_label.text = "Username and Password cannot be empty!"
            self.feedback_label.color = (1, 0, 0, 1)  # Set feedback label color to red to indicate an error
            return

        # Prepare the data to be sent to the server for registration
        data = {
            "username": username,
            "password": password
        }

        try:
            # Send a POST request to the /register/ endpoint with the provided data
            response = requests.post(f"{BASE_URL}/register/", json=data)

            # Check the server response status code and update the feedback label accordingly
            if response.status_code == 200:
                self.feedback_label.text = "Registration successful!"
                self.feedback_label.color = (0, 1, 0, 1)  # Set feedback label color to green to indicate success
            else:
                self.feedback_label.text = f"Registration failed: {response.json().get('detail', 'Unknown error')}"
                self.feedback_label.color = (1, 0, 0, 1)  # Set feedback label color to red to indicate an error
        except requests.exceptions.RequestException as e:
            # Handle any connection errors and update the feedback label with the error message
            self.feedback_label.text = f"Connection error: {str(e)}"
            self.feedback_label.color = (1, 0, 0, 1)  # Set feedback label color to red to indicate an error

    # Method for handling sending messages
    def send_message(self):
        # Get the sender ID (username), recipient ID, and encrypted message from the text input fields
        sender_id = self.username_input.text
        recipient_id = self.recipient_input.text
        encrypted_message = self.message_input.text

        # Check if any of the fields are empty
        if not sender_id or not recipient_id or not encrypted_message:
            self.feedback_label.text = "All fields must be filled!"
            self.feedback_label.color = (1, 0, 0, 1)  # Set feedback label color to red to indicate an error
            return

        # Prepare the data to be sent to the server for storing the message
        data = {
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "encrypted_message": encrypted_message,
            "timestamp": datetime.datetime.now().isoformat()  # Generate the current timestamp in ISO format
        }

        try:
            # Send a POST request to the /messages/ endpoint with the provided data
            response = requests.post(f"{BASE_URL}/messages/", json=data)

            # Check the server response status code and update the feedback label accordingly
            if response.status_code == 200:
                self.feedback_label.text = "Message sent successfully!"
                self.feedback_label.color = (0, 1, 0, 1)  # Set feedback label color to green to indicate success
            else:
                self.feedback_label.text = f"Failed to send message: {response.json().get('detail', 'Unknown error')}"
                self.feedback_label.color = (1, 0, 0, 1)  # Set feedback label color to red to indicate an error
        except requests.exceptions.RequestException as e:
            # Handle any connection errors and update the feedback label with the error message
            self.feedback_label.text = f"Connection error: {str(e)}"
            self.feedback_label.color = (1, 0, 0, 1)  # Set feedback label color to red to indicate an error


# Entry point to start the MessengerApp
if __name__ == '__main__':
    MessengerApp().run()
