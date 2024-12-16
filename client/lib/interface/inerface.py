import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QPushButton

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        # Set window title and dimensions
        self.setWindowTitle("PyQt6 Basic Window")
        self.setGeometry(100, 100, 300, 200)

        # Create a button
        close_button = QPushButton("Close", self)
        close_button.clicked.connect(self.close)  # Connect button to close event

        # Place the button in the bottom-right corner
        close_button.setGeometry(self.width() - 100, self.height() - 50, 80, 30)

if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Create and show the main window
    window = MainWindow()
    window.show()

    sys.exit(app.exec())
