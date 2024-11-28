# main.py

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button

# Define your FastAPI server base URL
BASE_URL = "http://127.0.0.1:8000"

# Messenger App using Kivy
class MessengerApp(App):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.layout = None
        self.username = None
        self.username_input = None
        self.password_input = None
        self.chat_partner_input = None
        self.chat_key_input = None

    def build(self):
        # Start with the login or register screen
        self.layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        self.username = None

        # Welcome label
        self.layout.add_widget(Label(text="Welcome to P2P Messenger"))

        # Create login and register buttons
        login_button = Button(text="Log In")
        register_button = Button(text="Register")

        # Bind buttons to their respective methods
        login_button.bind(on_press=self.show_login_screen)
        register_button.bind(on_press=self.show_register_screen)

        # Add buttons to the layout
        self.layout.add_widget(login_button)
        self.layout.add_widget(register_button)

        return self.layout

    def show_register_screen(self, _):
        # Clear the layout for registration screen
        self.layout.clear_widgets()
        self.layout.add_widget(Label(text="Register a new account"))

        # Add registration input fields
        self.username_input = TextInput(hint_text="Username", multiline=False)
        self.password_input = TextInput(hint_text="Password", multiline=False, password=True)
        self.layout.add_widget(self.username_input)
        self.layout.add_widget(self.password_input)

        # Add register button and go back button
        register_button = Button(text="Register")
        register_button.bind(on_press=self.register_user)
        go_back_button = Button(text="Go Back")
        go_back_button.bind(on_press=lambda x: self.build())  # Go back to main screen

        # Add buttons to the layout
        self.layout.add_widget(register_button)
        self.layout.add_widget(go_back_button)

    def show_login_screen(self, _):
        # Clear the layout for login screen
        self.layout.clear_widgets()
        self.layout.add_widget(Label(text="Log in to your account"))

        # Add login input fields
        self.username_input = TextInput(hint_text="Username", multiline=False)
        self.password_input = TextInput(hint_text="Password", multiline=False, password=True)
        self.layout.add_widget(self.username_input)
        self.layout.add_widget(self.password_input)

        # Add login button and go back button
        login_button = Button(text="Log In")
        login_button.bind(on_press=self.login_user)
        go_back_button = Button(text="Go Back")
        go_back_button.bind(on_press=lambda x: self.build())  # Go back to main screen

        # Add buttons to the layout
        self.layout.add_widget(login_button)
        self.layout.add_widget(go_back_button)

    def register_user(self, _):
        # Placeholder for registration logic
        username = self.username_input.text
        password = self.password_input.text
        if username and password:
            self.show_feedback("Registration successful!", color=(0, 1, 0, 1))
            self.build()  # Redirect to main screen
        else:
            self.show_feedback("Username and Password cannot be empty!", color=(1, 0, 0, 1))

    def show_feedback(self, message, color):
        # Generic method to show feedback messages to the user
        feedback_label = Label(text=message, color=color)
        self.layout.add_widget(feedback_label)

# Ensure to define all referenced methods before running the app to avoid attribute errors
if __name__ == "__main__":
    MessengerApp().run()
