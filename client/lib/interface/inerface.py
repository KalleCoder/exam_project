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

        # Create a CLOSE BUTTON
        close_button = QPushButton("Close Session", self)
        close_button.clicked.connect(self.close)  # Connect button to close event
        # Place the button in the top left corner
        close_button.setGeometry(10, 10, 110, 30)

        # Create a GET TEMPERATURE BUTTON
        temperature_button = QPushButton("Get Temperature", self)
        temperature_button.setGeometry(140, 10, 130, 30)
        temperature_button.clicked.connect(self.get_temperature)

        # Create a TOGGLE RELAY BUTTON
        relay_button = QPushButton("Toggle Relay", self)
        relay_button.setGeometry(290, 10, 130, 30)
        relay_button.clicked.connect(self.toggle_relay)

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
