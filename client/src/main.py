import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QPushButton, QTextEdit
from PyQt6.QtCore import Qt

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        # Set window title and dimensions
        self.setWindowTitle("Client")
        self.setGeometry(250, 250, 550, 450)

        # Set the background color of the window to white
        self.setStyleSheet("background-color: white; color: black;")

        # Session flag to track if the session is established or not
        self.session_active = False

        # Create a button for establishing/closing session
        self.session_button = QPushButton("Establish Session", self)
        self.session_button.clicked.connect(self.toggle_session)  # Connect button to toggle session event
        self.session_button.setGeometry(10, 10, 130, 30)

        # Create a GET TEMPERATURE BUTTON
        self.temperature_button = QPushButton("Get Temperature", self)
        self.temperature_button.setGeometry(150, 10, 130, 30)
        self.temperature_button.clicked.connect(self.get_temperature)

        # Create a TOGGLE RELAY BUTTON
        self.relay_button = QPushButton("Toggle Relay", self)
        self.relay_button.setGeometry(290, 10, 130, 30)
        self.relay_button.clicked.connect(self.toggle_relay)

        # Create the CLEAR TERMINAL BUTTON in the top-right corner
        clear_button = QPushButton("Clear Terminal", self)
        clear_button.setGeometry(self.width() - 120, 20, 120, 25)  # Position it in the top-right
        clear_button.clicked.connect(self.clear_terminal)

        # Create the terminal-like text box
        self.terminal = QTextEdit(self)
        self.terminal.setGeometry(10, 50, 530, 390)  # Place it below the buttons
        self.terminal.setStyleSheet("background-color: black; color: white;")  # Set background to black, text to white
        self.terminal.setReadOnly(True)  # Make the text box read-only, so the user can't type in it

        # Style the Clear button to look like text
        clear_button.setStyleSheet("""
            QPushButton {
                background: none;
                border: none;
                color: blue;
                font: 10pt; 
            }
            QPushButton:hover {
                color: #FFD700;
            }
        """)

        # Apply styles for disabled buttons to look "washed out"
        self.setStyleSheet("""
            QPushButton:disabled {
                background-color: lightgray;
                color: darkgray;
                border: 1px solid gray;
            }
        """)

        # Initialize buttons as disabled
        self.temperature_button.setEnabled(False)
        self.relay_button.setEnabled(False)

    def toggle_session(self):
        """Toggle between establishing and closing the session."""
        if self.session_active:
            self.session_active = False
            self.session_button.setText("Establish Session")  # Change button text to "Establish Session"
            self.terminal.append("Session Closed")  # Print to terminal

            # Disable the other buttons
            self.temperature_button.setEnabled(False)
            self.relay_button.setEnabled(False)
        else:
            self.session_active = True
            self.session_button.setText("Close Session")  # Change button text to "Close Session"
            self.terminal.append("Session Established")  # Print to terminal

            # Enable the other buttons
            self.temperature_button.setEnabled(True)
            self.relay_button.setEnabled(True)

    def get_temperature(self):
        self.terminal.append("Temperature: 22°C")  # Simulate printing the temperature

    def toggle_relay(self):
        self.terminal.append("Relay toggled")  # Simulate toggling the relay

    def clear_terminal(self):
        self.terminal.clear()  # Clear the terminal text box


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Create and show the main window
    window = MainWindow()
    window.show()

    sys.exit(app.exec())
