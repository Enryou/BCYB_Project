# main.py

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
import requests

# Define your FastAPI server base URL
BASE_URL = "http://127.0.0.1:8000"

class MessengerApp(App):
    def __init__(self, **kwargs):
        super(MessengerApp, self).__init__(**kwargs)
        # Initialize all attributes
        self.layout = None
        self.username_input = None
        self.password_input = None
        self.feedback_label = None

    def build(self):
        # Start with the login or register screen
        self.layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        self.layout.add_widget(Label(text="Welcome to P2P Messenger"))

        # Create login and register buttons
        login_button = Button(text="Log In")
        register_button = Button(text="Register")

        login_button.bind(on_press=self.show_login_screen)
        register_button.bind(on_press=self.show_register_screen)

        self.layout.add_widget(login_button)
        self.layout.add_widget(register_button)

        return self.layout

    def show_input_screen(self, title, action_button_text, action_callback):
        # Generic method to create a screen for either login or registration
        self.layout.clear_widgets()
        self.layout.add_widget(Label(text=title))

        self.username_input = TextInput(hint_text="Username", multiline=False)
        self.password_input = TextInput(hint_text="Password", multiline=False, password=True)

        self.layout.add_widget(self.username_input)
        self.layout.add_widget(self.password_input)

        action_button = Button(text=action_button_text)
        action_button.bind(on_press=action_callback)
        self.layout.add_widget(action_button)

    def show_register_screen(self, _):
        # Use generic input screen for registration
        self.show_input_screen("Register a new account", "Register", self.register_user)

    def show_login_screen(self, _):
        # Use generic input screen for login
        self.show_input_screen("Log in to your account", "Log In", self.login_user)

    def register_user(self, _):
        # Get the username and password from the text input fields
        username, password = self.get_user_credentials()

        # Check if the username or password fields are empty
        if not username or not password:
            self.display_feedback("Username and Password cannot be empty!", error=True)
            return

        # Prepare the data to be sent to the server for registration
        data = {
            "username": username,
            "password": password
        }

        try:
            # Send a POST request to the /register/ endpoint with the provided data
            response = requests.post(url=f"{BASE_URL}/register/", json=data)

            # Check the server response status code and update the feedback label accordingly
            if response.status_code == 200:
                self.display_feedback("Registration successful!", error=False)
            elif response.status_code == 409:
                self.display_feedback("Username already taken. Choose another one.", error=True)
            else:
                self.display_feedback(f"Registration failed: {response.json().get('detail', 'Unknown error')}", error=True)
        except requests.exceptions.RequestException as e:
            self.display_feedback(f"Connection error: {str(e)}", error=True)

    def login_user(self, _):
        # Get the username and password from the text input fields
        username, password = self.get_user_credentials()

        if not username or not password:
            self.display_feedback("Username and Password cannot be empty!", error=True)
            return

        data = {"username": username, "password": password}
        try:
            response = requests.post(url=f"{BASE_URL}/login/", json=data)
            if response.status_code == 200:
                self.display_feedback("Login successful!", error=False)
            else:
                self.display_feedback("Login failed. Please check your credentials.", error=True)
        except requests.exceptions.RequestException as e:
            self.display_feedback(f"Connection error: {str(e)}", error=True)

    def get_user_credentials(self):
        # Helper function to get username and password from input fields
        return self.username_input.text, self.password_input.text

    def display_feedback(self, message, error=True):
        # Helper function to display feedback messages
        if self.feedback_label:
            self.layout.remove_widget(self.feedback_label)
        self.feedback_label = Label(text=message, color=(1, 0, 0, 1) if error else (0, 1, 0, 1))
        self.layout.add_widget(self.feedback_label)

if __name__ == '__main__':
    MessengerApp().run()
