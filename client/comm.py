import time
import random
from mbedtls import pk, hashlib
import serial
import argparse
import hmac

AES_SIZE = 32
RSA_SIZE = 256
_EXPONENT = 65537
HASH_SIZE = 32
_SECRET_KEY = b"Fj2-;wu3Ur=ARl2!Tqi6IuKM3nG]8z1+"


class Communication:
    def __init__(self, port, baudrate):
        self.serial_connection = serial.Serial(port, baudrate, timeout=1)
        self.session_active = False

        # Security parameters
        self.iv = random.randbytes(16)  # Random AES IV
        self.rsa_keys = pk.RSA()  # Create RSA keys
        self.rsa_keys.generate(RSA_SIZE * 8, _EXPONENT)
        self.aes_key = random.randbytes(AES_SIZE)  # Random AES Key

        # Client's public and private key
        self.client_public_key = self.rsa_keys.export_public_key(format="DER")  # Public key in DER format
        self.server_pub_key = None  # Placeholder for the server's public key
        print(f"Public key size: {len(self.client_public_key)} bytes")

        # Iterate over each byte in the byte string and print it as a hexadecimal string
        for byte in _SECRET_KEY:
            print(f'{byte:02X}', end=' ') 


    def encrypt_with_private_key(self, data):
        """ Encrypt data with the client's private key (signing) """
        return self.rsa_keys.sign(data, "SHA256")


    def encrypt_with_public_key(self, data, public_key):
        """ Encrypt data with a public key (server's public key) """
        rsa = pk.RSA()
        rsa.import_key(public_key, format="der")
        return rsa.encrypt(data)


    def decrypt_with_private_key(self, data):
        """ Decrypt data with the client's private key """
        return self.client_priv_key.decrypt(data)


    def hash_data(self, data):
        """ Hash the data using SHA-256 """
        return hashlib.sha256(data).digest()

    def send_public_key(self):
        """ Send the client's public key using the HVAC key for signing and its hash """
        # Sign the public key with the HVAC key using HMAC and SHA-256
        hmac_object = hmac.new(_SECRET_KEY, self.client_public_key, hashlib.sha256)
        signed_pub_key = hmac_object.digest()  # Get the digest (signed result)
        
        # Hash the signed public key to send its hash
        signed_pub_key_hash = self.hash_data(self.client_public_key)

        # Print the size (in bytes) of the data being written
        print(f"Size of public_key_der (public key): {len(self.client_public_key)} bytes")
        print(f"Size of signed_pub_key: {len(signed_pub_key)} bytes")
        print(f"Size of signed_pub_key_hash: {len(signed_pub_key_hash)} bytes")

        # Log the actual byte content
        print(f"Sending public key (hex): {self.client_public_key.hex()}")
        print(f"Sending signed_pub_key (hex): {signed_pub_key.hex()}")
        print(f"Sending signed_pub_key_hash (hex): {signed_pub_key_hash.hex()}")

        # Send the public key, signed public key, and its hash
        """ time.sleep(2)
        self.serial_connection.write(self.client_keys)  # Send the actual public key
        self.serial_connection.flush()  # Ensure data is written out of the buffer """

        chunk_size = 64
        for i in range(0, len(self.client_public_key), chunk_size):
            self.serial_connection.write(self.client_public_key[i:i + chunk_size])
            self.serial_connection.flush()
            time.sleep(0.5)  # Allow the server to process each chunk

        self.serial_connection.flush()
        time.sleep(1)
        self.serial_connection.write(signed_pub_key)  # Send the signed public key
        self.serial_connection.flush()  # Ensure signature is written out
        time.sleep(2)
        self.serial_connection.write(signed_pub_key_hash)  # Send the hash
        self.serial_connection.flush()  # Ensure hash is written out """

        return True


    def receive_server_public_key(self):
        """Receive, decrypt, and validate the server's public key."""
        print("Receiving server public key parts...")

        # Receive the encrypted parts of the server's public key
        encrypted_part1 = self.serial_connection.read(RSA_SIZE)
        encrypted_part2 = self.serial_connection.read(RSA_SIZE)

        if len(encrypted_part1) != RSA_SIZE or len(encrypted_part2) != RSA_SIZE:
            print("Error: Received parts are not of expected RSA size.")
            return False

        # Receive the hash of the server's public key
        received_hash = self.serial_connection.read(HASH_SIZE)

        if len(received_hash) != HASH_SIZE:
            print("Error: Received hash is not of expected size.")
            return False

        # Decrypt the two parts
        print("Decrypting the server public key parts...")
        decrypted_part1 = self.rsa_keys.decrypt(encrypted_part1)
        decrypted_part2 = self.rsa_keys.decrypt(encrypted_part2)

        # Combine the decrypted parts to reconstruct the server public key
        server_pub_key = decrypted_part1 + decrypted_part2

        # Validate the received hash
        print("Validating hash of the reconstructed server public key...")
        computed_hash = hmac.new(_SECRET_KEY, server_pub_key, hashlib.sha256).digest()

        if computed_hash != received_hash:
            print("Error: Hash validation failed.")
            return False

        # Store the server's public key
        self.server_pub_key = server_pub_key
        print("Server public key successfully received and validated.")

        return True


    def send_new_public_key(self):
        """ Send the new encrypted client public key and hash to the server """
        # Generate a new key pair
        self.rsa_keys.generate(RSA_SIZE * 8, _EXPONENT)
        new_client_pub_key = self.rsa_keys.export_public_key()

        # Encrypt the new public key using the server's public key
        encrypted_new_pub_key = self.encrypt_with_public_key(new_client_pub_key, self.server_pub_key)

        # Hash the encrypted new public key before sending
        new_pub_key_hash = self.hash_data(encrypted_new_pub_key)

        # Send the encrypted new public key and its hash to the server
        self.serial_connection.write(encrypted_new_pub_key)
        self.serial_connection.write(new_pub_key_hash)

        return True

def startup():
    # Initialize serial communication and communication object
    parser = argparse.ArgumentParser(description="Start the client application.")
    parser.add_argument('port', type=str, help="Communication port (e.g., COM3 or /dev/ttyUSB0)")
    parser.add_argument('baudrate', type=int, help="Baud rate (e.g., 9600 or 115200)")
    args = parser.parse_args()
    
    comm = Communication(port=args.port, baudrate=args.baudrate)

    if not comm.send_public_key():
            print("Error in sending encrypted public key.")
            time.sleep(1)


    """ while True:
        if not comm.send_public_key():
            print("Error in sending encrypted public key.")
            time.sleep(1)

           if comm.serial_connection.in_waiting > 0:
            encrypted_server_pub_key, server_pub_key_hash = comm.receive_server_public_key()

            decrypted_server_pub_key = comm.decrypt_server_public_key(encrypted_server_pub_key)
            if decrypted_server_pub_key is None:
                print("Error decrypting server public key.")
                continue

            print(f"Decrypted server public key: {decrypted_server_pub_key}")

            if not comm.verify_received_hash(encrypted_server_pub_key, server_pub_key_hash):
                print("Hash verification failed!")
                continue

            print("Hash verification passed!")

            if not comm.send_new_public_key():
                print("Error in sending new public key.")
            else:
                print("Key exchange process completed.")
                break  
        else:
            print("Sent public key.")
            time.sleep(1)  """

if __name__ == "__main__":
    startup()


