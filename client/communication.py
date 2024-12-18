

""" Session Integrity: Consider adding a mechanism to check if the session is still valid (e.g., through periodic heartbeat messages). 
It could also be useful to authenticate the server to avoid man-in-the-middle attacks. """

""" Session Expiration: Consider implementing a session timeout or expiration mechanism, 
ensuring that an attacker can't reuse a long-lived session key. """

import time
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
        self.hash = None
        self.hmac = None
        self.iv = random.randbytes(16)
        self.rsa_keys = pk.RSA()
        self.rsa_keys.generate(RSA_SIZE * 8, _EXPONENT)
        self.aes_key = random.randbytes(AES_SIZE)

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


    # ============ AES ====================
    # AES encryption method
    def aes_encrypt(self, data):
        """Encrypt data using AES with CBC mode."""
        aes = cipher.AES.new(self.aes_key, cipher.MODE_CBC, self.iv)
        # Pad the data to be a multiple of block size (16 bytes)
        pad_length = 16 - (len(data) % 16)
        padded_data = data + bytes([pad_length] * pad_length)
        encrypted_data = aes.encrypt(padded_data)
        return encrypted_data

    # AES decryption method
    def aes_decrypt(self, encrypted_data):
        """Decrypt data using AES with CBC mode."""
        aes = cipher.AES.new(self.aes_key, cipher.MODE_CBC, self.iv)
        decrypted_data = aes.decrypt(encrypted_data)
        
        # Remove padding
        pad_length = decrypted_data[-1]
        return decrypted_data[:-pad_length]



    # =========== STARTUP ============
    def start_session(self):
        """Start a secure session with the server."""

        self.session_start_time = time.time() 

        if not self.serial_connection.is_open:
            self.serial_connection.open()

        # Step 1: Generate AES key and IV (one time for the session)
        self.aes_key = random.randbytes(AES_SIZE)  # Generate AES key
        self.iv = random.randbytes(16)  # Generate IV for AES

        # Step 2: Encrypt the AES key and IV using RSA
        encrypted_aes_key = self.rsa_encrypt(self.aes_key)
        encrypted_iv = self.rsa_encrypt(self.iv)

        # Step 3: Send public RSA key to the server
        public_key = self.rsa_keys.export_public_key(format='DER')
        print(f"Public key size: {len(public_key)}")  # Check the length
        self.serial_connection.write(public_key)
        print("Public key sent to server.")

        time.sleep(1)  # Add a 1-second delay to give the server time to process

        # Step 4: Send encrypted AES key and IV
        self.serial_connection.write(encrypted_aes_key)
        time.sleep(1)
        self.serial_connection.write(encrypted_iv)
        print(f"Encrypted AES key size: {len(encrypted_aes_key)}")
        print(f"Encrypted IV size: {len(encrypted_iv)}")


        # Step 5: Wait for server acknowledgment
        response = self.serial_connection.readline().strip()
        if response == b"ACK":
            print("Session established.")
            self.session_active = True
        else:
            print("Failed to establish session.")

    # This needs to reset time every time I press a button
    def check_session_timeout(self):
        """Check if the session has timed out."""
        if time.time() - self.session_start_time > 60: #   SESSION_TIMEOUT:
            self.close_session()  # Close session if timed out
            raise RuntimeError("Session has expired.")
        
    def heartbeat_check(self):
        """Send a heartbeat at regular intervals to check if the session is still active."""
        if not self.session_active:
            raise RuntimeError("Session not active.")
        
        while self.session_active:
            self.serial_connection.write(b"HEARTBEAT")
            print("Heartbeat sent.")
            time.sleep(30)  # Wait for 30 seconds before sending the next heartbeat




    # ============ SENDING MESSAGE ============
    def send_message(self, message):
        """Send a secure message to the server."""
        # AES encryption
        aes = cipher.AES.new(self.aes_key, cipher.MODE_CBC, self.ivec)
        plen = cipher.AES.block_size - (len(message) % cipher.AES.block_size)
        encrypted_message = aes.encrypt(message + bytes(plen))

        # Generate HMAC for message integrity
        hmac_value = self.hmac_sha256(encrypted_message)

        # RSA encryption (for AES key and IV)
        encrypted_aes_key = self.rsa_keys.encrypt(self.aes_key)
        encrypted_iv = self.rsa_keys.encrypt(self.ivec)

        # Send data using multiple buffers
        self.serial_connection.write(encrypted_aes_key)
        self.serial_connection.write(encrypted_iv)
        self.serial_connection.write(encrypted_message)
        self.serial_connection.write(hmac_value)  # Send HMAC for integrity

    # ============ RECIEVING MESSAGE ===========
    def receive_message(self):
        """Receive and decrypt a message from the server."""
        if not self.session_active:
            raise RuntimeError("No active session.")
        # Wait for data to be available in the serial buffer
        while not self.serial_connection.in_waiting:
            time.sleep(0.1)  # Small delay to avoid busy-waiting

        # Receive encrypted data (AES key, IV, message)
        encrypted_aes_key = self.serial_connection.read(RSA_SIZE)
        encrypted_iv = self.serial_connection.read(RSA_SIZE)
        encrypted_message = self.serial_connection.read()

        # Receive HMAC value for integrity verification
        received_hmac = self.serial_connection.read(32)  # Assuming 32-byte HMAC for SHA256

        # Decrypt AES key and IV using RSA
        aes_key = self.rsa_keys.decrypt(encrypted_aes_key)
        iv = self.rsa_keys.decrypt(encrypted_iv)

        # Decrypt message using AES
        aes = cipher.AES.new(aes_key, cipher.MODE_CBC, iv)
        decrypted_message = aes.decrypt(encrypted_message)

        # Verify HMAC for integrity
        expected_hmac = self.hmac_sha256(decrypted_message)
        if expected_hmac != received_hmac:
            raise RuntimeError("Message integrity check failed")

        # Remove padding and return message
        padding_len = decrypted_message[-1]
        return decrypted_message[:-padding_len]

    # ================= CLOSE SESSION =========
    def close_session(self):
        """Close the session and the serial connection."""
        if self.session_active:
            self.serial_connection.write(b"CLOSE")
            print("Session closed.")
            self.session_active = False
        #self.serial_connection.close() # Maybe remove this here!


