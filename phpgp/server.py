import os
import sys
import json
import base64
import socket
import logging
import threading
import platform

from pgpy import PGPKey, PGPMessage
from pgpy.constants import HashAlgorithm, SignatureType

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Determine socket paths based on the OS
if platform.system() == "Windows":
    HOST = "127.0.0.1"
    PORT = 65432
else:
    SOCKET_PATH = "/tmp/phpgp.sock"


def start_server(private_key_data, public_key_data, passphrase):
    """
    Starts the phpgp server which handles signing, encryption, and decryption
    requests via TCP (on Windows) or Unix Domain Socket (on Unix-like systems).

    :param private_key_data: str, armored private key
    :param public_key_data: str, armored public key
    :param passphrase: str, passphrase to unlock the private key
    """
    # Parse the keys from the provided data
    private_key, _ = PGPKey.from_blob(private_key_data)
    public_key, _ = PGPKey.from_blob(public_key_data)

    # Unlock the private key if it is protected
    if private_key.is_protected:
        try:
            unlocked = private_key.unlock(passphrase)
            if unlocked:
                logger.info("Private key successfully unlocked.")
            else:
                logger.error(
                    "Failed to unlock the private key. Check the passphrase.")
                sys.exit(1)
        except Exception as e:
            logger.error(f"Exception during unlocking key: {e}")
            sys.exit(1)
    else:
        logger.info("Private key is not protected by a passphrase.")

    def handle_client_connection(client_socket, address=None):
        """
        Handles individual client connections. Receives a JSON request,
        interprets the 'operation' field, and responds accordingly with
        a JSON response.
        """
        try:
            logger.info(f"Connection from {address}")
            # Increase buffer size for large data
            data = client_socket.recv(65536).decode()
            if not data:
                logger.info("No data received.")
                response = {"error": "No data received."}
                client_socket.sendall(json.dumps(response).encode())
                return

            request = json.loads(data)
            operation = request.get("operation")
            response = {}

            if operation == "sign":
                # SIGN operation
                encoded_data = request.get("data")
                if not encoded_data:
                    response["error"] = "No data provided for signing."
                else:
                    # Decode data from base64 to bytes
                    data_bytes = base64.b64decode(encoded_data)
                    # Create a PGPMessage from the raw bytes
                    message = PGPMessage.new(data_bytes, file=True)
                    # Sign with detached=True for a detached signature
                    if private_key.is_protected:
                        with private_key.unlock(passphrase):
                            signature = private_key.sign(
                                message,
                                detached=True,
                                hash=HashAlgorithm.SHA256,
                                signature_type=SignatureType.BinaryDocument
                            )
                    else:
                        signature = private_key.sign(
                            message,
                            detached=True,
                            hash=HashAlgorithm.SHA256,
                            signature_type=SignatureType.BinaryDocument
                        )
                    response["signature"] = str(signature)

            elif operation == "encrypt":
                # ENCRYPT operation
                message_data = request.get("data")
                recipient_key_data = request.get("recipient_key")
                if not message_data or not recipient_key_data:
                    response["error"] = "Data or recipient_key not provided for encryption."
                else:
                    recipient_key, _ = PGPKey.from_blob(recipient_key_data)
                    message = PGPMessage.new(message_data)
                    if private_key.is_protected:
                        with private_key.unlock(passphrase):
                            encrypted_message = recipient_key.encrypt(message)
                    else:
                        encrypted_message = recipient_key.encrypt(message)
                    response["encrypted"] = str(encrypted_message)

            elif operation == "decrypt":
                # DECRYPT operation
                encrypted_data = request.get("data")
                if not encrypted_data:
                    response["error"] = "No data provided for decryption."
                else:
                    try:
                        encrypted_message = PGPMessage.from_blob(
                            encrypted_data)
                        if private_key.is_protected:
                            with private_key.unlock(passphrase):
                                decrypted_message = private_key.decrypt(
                                    encrypted_message)
                        else:
                            decrypted_message = private_key.decrypt(
                                encrypted_message)

                        if decrypted_message.ok:
                            response["decrypted"] = str(
                                decrypted_message.message)
                        else:
                            response["error"] = "Decryption failed."
                    except Exception as e:
                        response["error"] = f"Decryption error: {str(e)}"
            else:
                response["error"] = f"Unsupported operation: {operation}"

            response_data = json.dumps(response)
            client_socket.sendall(response_data.encode())
            logger.info(f"Processed {operation} operation from {address}")
        except json.JSONDecodeError:
            response = {"error": "Invalid JSON format."}
            client_socket.sendall(json.dumps(response).encode())
            logger.error("Received invalid JSON.")
        except Exception as e:
            response = {"error": str(e)}
            client_socket.sendall(json.dumps(response).encode())
            logger.error(f"Error processing request from {address}: {e}")
        finally:
            client_socket.close()

    # Start the server depending on the OS
    if platform.system() == "Windows":
        # Use TCP socket on Windows
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            try:
                server.bind((HOST, PORT))
                server.listen()
                logger.info(f"phpgp signing server started on {HOST}:{PORT}")
            except Exception as e:
                logger.error(f"Failed to bind server on {HOST}:{PORT}: {e}")
                sys.exit(1)

            while True:
                client, addr = server.accept()
                client_handler = threading.Thread(
                    target=handle_client_connection,
                    args=(client, addr)
                )
                client_handler.start()
    else:
        # Use Unix Domain Socket on Unix-like systems
        if os.path.exists(SOCKET_PATH):
            os.remove(SOCKET_PATH)

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            try:
                server.bind(SOCKET_PATH)
                server.listen()
                logger.info(f"phpgp signing server started on {SOCKET_PATH}")
            except Exception as e:
                logger.error(f"Failed to bind server on {SOCKET_PATH}: {e}")
                sys.exit(1)

            while True:
                client, _ = server.accept()
                client_handler = threading.Thread(
                    target=handle_client_connection,
                    args=(client,)
                )
                client_handler.start()


if __name__ == "__main__":
    # Retrieve environment variables for private/public keys and passphrase
    private_key_data = os.getenv("PRIVATE_KEY")
    public_key_data = os.getenv("PUBLIC_KEY")
    private_key_passphrase = os.getenv("PRIVATE_KEY_PASSPHRASE")

    if not private_key_data or not public_key_data:
        logger.error(
            "PRIVATE_KEY and PUBLIC_KEY environment variables must be set.")
        sys.exit(1)

    if private_key_passphrase:
        start_server(private_key_data, public_key_data, private_key_passphrase)
    else:
        start_server(private_key_data, public_key_data, "")
