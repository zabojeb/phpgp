# This code is part of the phpgp project: <https://github.com/zabojeb/phpgp>
#
# Copyright (C) 2024-2025 Yaroslav Voropaev <zabojeb@bk.ru>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import os
import sys
import json
import base64
import socket
import logging
import threading
import platform

import ctypes

from pgpy import PGPKey, PGPMessage
from pgpy.constants import HashAlgorithm, SignatureType

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Determine socket paths based on the OS
if platform.system() == "Windows":
    HOST = "127.0.0.1"
    PORT = 65432
else:
    import resource
    SOCKET_PATH = "/tmp/phpgp.sock"

# Store original key data at the module level
ORIGINAL_PRIVATE_KEY_DATA = None
ORIGINAL_PUBLIC_KEY_DATA = None
KEYS_REMOVED_FROM_DRIVE = True


def apply_security_measures():
    """
    Apply OS-level security measures to protect the server process.
    """
    system = platform.system()

    if system != "Windows":
        # 1. Disable core dumps
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            logger.info("Core dumps have been disabled.")
        except Exception as e:
            logger.warning(f"Could not disable core dumps: {e}")

        # 2. Set process as non-dumpable (Linux-specific)
        try:
            libc = ctypes.CDLL("libc.so.6")
            PR_SET_DUMPABLE = 4
            libc.prctl(PR_SET_DUMPABLE, 0)
            logger.info("Process has been set to non-dumpable (prctl).")
        except Exception as e:
            logger.warning(f"Could not set process non-dumpable: {e}")

        # 3. Lock memory to prevent swapping (mlockall)
        try:
            libc = ctypes.CDLL("libc.so.6")
            MCL_CURRENT = 1
            MCL_FUTURE = 2
            res = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
            if res == 0:
                logger.info("Memory has been locked (mlockall).")
            else:
                logger.warning("mlockall failed. You may lack sufficient privileges.")
        except Exception as e:
            logger.warning(f"Could not lock memory: {e}")

        # 4. Set resource limits
        try:
            # Ограничение количества открытых файлов
            resource.setrlimit(resource.RLIMIT_NOFILE, (100, 100))
            # Ограничение количества процессов/потоков
            resource.setrlimit(resource.RLIMIT_NPROC, (50, 50))
            logger.info("Resource limits have been set.")
        except Exception as e:
            logger.warning(f"Could not set resource limits: {e}")
    else:
        logger.info("Windows OS detected. Skipping Unix-specific hardening measures.")

def start_server(private_key_data, public_key_data, passphrase):
    """
    Starts the phpgp server which handles signing, encryption, and decryption
    requests via TCP (on Windows) or Unix Domain Socket (on Unix-like systems).

    :param private_key_data: str, armored private key
    :param public_key_data: str, armored public key
    :param passphrase: str, passphrase to unlock the private key
    """

    apply_security_measures()

    global ORIGINAL_PRIVATE_KEY_DATA
    global ORIGINAL_PUBLIC_KEY_DATA

    ORIGINAL_PRIVATE_KEY_DATA = private_key_data
    ORIGINAL_PUBLIC_KEY_DATA = public_key_data

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

            elif operation == "restore":
                # Key restoring operation
                # well, actually we should do smthn with KEYS_REMOVED_FROM_DRIVE based on user's choice
                # but we don't
                if KEYS_REMOVED_FROM_DRIVE:
                    response["private_key_data"] = ORIGINAL_PRIVATE_KEY_DATA
                    response["public_key_data"] = ORIGINAL_PUBLIC_KEY_DATA
                else:
                    response["error"] = "Keys were not removed from the drive. Nothing to restore."

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
                logger.info(f"phpgp server started on {HOST}:{PORT}")
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
                logger.info(f"phpgp server started on {SOCKET_PATH}")
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
