import sys
import argparse
from PyQt6.QtWidgets import QApplication, QMainWindow, QPushButton, QTextEdit
#from PyQt6.QtCore import Qt
from communication import Communication 

class MainWindow(QMainWindow):
    def __init__(self, port, baudrate):
        super().__init__()

        # Set window title and dimensions
        self.setWindowTitle("Client")
        self.setGeometry(250, 250, 550, 450)

        # Set the background color of the window to white
        self.setStyleSheet("background-color: white; color: black;")

        # Initialize Communication class
        try:
            self.communication = Communication(port=port, baudrate=baudrate)
        except Exception as e:
            print(f"Error initializing Communication: {e}")
            self.communication = None

        self.session_active = False

        # Create session button
        self.session_button = QPushButton("Establish Session", self)
        self.session_button.clicked.connect(self.toggle_session)
        self.session_button.setGeometry(10, 10, 130, 30)

        # Create temperature button
        self.temperature_button = QPushButton("Get Temperature", self)
        self.temperature_button.setGeometry(150, 10, 130, 30)
        self.temperature_button.clicked.connect(self.get_temperature)

        # Create relay button
        self.relay_button = QPushButton("Toggle Relay", self)
        self.relay_button.setGeometry(290, 10, 130, 30)
        self.relay_button.clicked.connect(self.toggle_relay)

        # Create clear button
        clear_button = QPushButton("Clear Terminal", self)
        clear_button.setGeometry(self.width() - 120, 20, 120, 25)
        clear_button.clicked.connect(self.clear_terminal)

        # Create terminal
        self.terminal = QTextEdit(self)
        self.terminal.setGeometry(10, 50, 530, 390)
        self.terminal.setStyleSheet("background-color: black; color: white;")
        self.terminal.setReadOnly(True)

        # Style the clear button
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
        if self.session_active:
            self.communication.close_session()
            self.session_active = False
            self.session_button.setText("Establish Session")
            self.terminal.append("Session Closed")
            self.temperature_button.setEnabled(False)
            self.relay_button.setEnabled(False)
        else:
            try:
                self.communication.start_session()
                if self.communication.session_active:
                    self.session_active = True
                    self.session_button.setText("Close Session")
                    self.terminal.append("Session Established")
                    self.temperature_button.setEnabled(True)
                    self.relay_button.setEnabled(True)
            except Exception as e:
                self.terminal.append(f"Failed to establish session: {e}")

    def get_temperature(self):
        try:
            temperature = self.communication.request_temperature()
            self.terminal.append(f"Temperature: {temperature}°C")
        except Exception as e:
            self.terminal.append(f"Error retrieving temperature: {e}")

    def toggle_relay(self):
        try:
            self.communication.send_message("TOGGLE_RELAY")
            self.terminal.append("Relay toggled")
        except Exception as e:
            self.terminal.append(f"Error toggling relay: {e}")

    def clear_terminal(self):
        self.terminal.clear()


if __name__ == "__main__":
    # Setup argument parser
    parser = argparse.ArgumentParser(description="Start the client application.")
    parser.add_argument('port', type=str, help="Communication port (e.g., COM3 or /dev/ttyUSB0)")
    parser.add_argument('baudrate', type=int, help="Baud rate (e.g., 9600 or 115200)")
    
    # Parse arguments
    args = parser.parse_args()

    # Create the application
    app = QApplication(sys.argv)

    # Create the main window, passing the arguments to the Communication class
    window = MainWindow(port=args.port, baudrate=args.baudrate)
    window.show()

    # Run the application
    sys.exit(app.exec())

