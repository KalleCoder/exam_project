# press the button in main --> pack it into buffer in security --> send request
# recieve buffer --> unpack it in the security --> show the data

# communication class only gets the data

# security unpacks or packs

# main just shows the gui

import random
from mbedtls import pk, hmac, hashlib, cipher
import serial

AES_SIZE = 32
RSA_SIZE = 256
_EXPONENT = 65537
_SECRET_KEY = b"Fj2-;wu3Ur=ARl2!Tqi6IuKM3nG]8z1+"

class Communication:
    def __init__(self, port, baudrate):
        self.serial_connection = serial.Serial(port, baudrate, timeout=1)
        self.session_active = False

        # Security parameters
        self.aes_key = random.randbytes(AES_SIZE)
        self.iv = random.randbytes(16)
        self.rsa_keys = pk.RSA()
        self.rsa_keys.generate(RSA_SIZE * 8, _EXPONENT)
        self.hash = None
        self.hmac = None

    # ============ SHA256 HASH ==============
    def sha256_hash(self, data):
        """Generate a SHA256 hash of the given data."""

        sha256 = hashlib.sha256()
        sha256.update(data)
        self.hash = sha256.digest()
        return self.hash

    # ============ HMAC_SHA256 ==============
    def hmac_sha256(self, message):
        """Generate HMAC using SHA256 and the secret key."""

        hash_instance = hashlib.sha256()
        hash_instance.update(_SECRET_KEY)
        hmac_instance = hmac.new(hash_instance.digest(), digestmod="SHA256")
        hmac_instance.update(message)
        self.hmac = hmac_instance.digest()
        return self.hmac

    # ============= RSA ====================
    def rsa_encrypt(self, message):
        """Encrypt a message using the public RSA key."""

        return self.rsa_keys.encrypt(message)

    def rsa_decrypt(self, cipher_text):
        """Decrypt a message using the private RSA key."""

        return self.rsa_keys.decrypt(cipher_text)


    # =========== STARTUP ============
    def start_session(self):
        """Start a secure session with the server."""

        if not self.serial_connection.is_open:
            self.serial_connection.open()

        # Step 1: Send public RSA key to the server
        public_key = self.rsa_keys.export_public_key()
        self.serial_connection.write(public_key)
        print("Public key sent to server.")

        # Step 2: Wait for server acknowledgment
        response = self.serial_connection.readline().strip()
        if response == b"ACK":
            print("Session established.")
            self.session_active = True
        else:
            print("Failed to establish session.")


    # ============ SENDING MESSAGE ============
    def send_message(self, message):
        """Send a secure message to the server."""
        if not self.session_active:
            raise RuntimeError("No active session.")
        
        # HMAC generation for message integrity
        message_hmac = self.hmac_sha256(message.encode('utf-8'))

        # Encrypt the message and its HMAC
        combined_message = message.encode('utf-8') + b"||" + message_hmac
        cipher_text = self.rsa_encrypt(combined_message)
        self.serial_connection.write(cipher_text)
        print(f"Encrypted message sent: {cipher_text.hex()}")

    # ============ RECIEVING MESSAGE ===========
    def receive_message(self):
        """Receive and decrypt a message from the server."""
        if not self.session_active:
            raise RuntimeError("No active session.")
        
        # Receive cipher text
        cipher_text = self.serial_connection.read(RSA_SIZE)
        decrypted_data = self.rsa_decrypt(cipher_text)

        # Separate message and HMAC
        message, received_hmac = decrypted_data.rsplit(b"||", 1)

        # Verify HMAC
        expected_hmac = self.hmac_sha256(message)
        if received_hmac != expected_hmac:
            raise ValueError("Message integrity check failed!")
        
        print(f"Received message: {message.decode('utf-8')}")
        return message.decode('utf-8')


    # ================= CLOSE SESSION =========
    def close_session(self):
        """Close the session and the serial connection."""
        if self.session_active:
            self.serial_connection.write(b"CLOSE")
            print("Session closed.")
            self.session_active = False
        self.serial_connection.close()

# Example usage
if __name__ == "__main__":
    # Replace 'COM3' with the appropriate port for your server
    comm = Communication(port='COM3')
    comm.start_session()

    if comm.session_active:
        comm.send_message("Hello, Server!")
        comm.receive_message()

    comm.close_session()

