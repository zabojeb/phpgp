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

# ---- Secure, pure in-memory keyring backend ----
import keyring.backend


class InMemoryKeyring(keyring.backend.KeyringBackend):
    """ A per-process, in-memory keyring (never persisted to disk). """
    priority = 10
    _storage = dict()

    def get_password(self, servicename, username):
        return self._storage.get((servicename, username), None)

    def set_password(self, servicename, username, password):
        self._storage[(servicename, username)] = password

    def delete_password(self, servicename, username):
        try:
            del self._storage[(servicename, username)]
        except KeyError:
            raise keyring.errors.PasswordDeleteError


keyring.set_keyring(InMemoryKeyring())

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phpgp.server")

if platform.system() == "Windows":
    HOST = "127.0.0.1"
    PORT = 65432
else:
    import resource
    SOCKET_PATH = "/tmp/phpgp.sock"


def apply_security_measures():
    system = platform.system()
    if system != "Windows":
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            logger.info("Core dumps have been disabled.")
        except Exception as e:
            logger.warning(f"Could not disable core dumps: {e}")
        try:
            libc = ctypes.CDLL("libc.so.6")
            PR_SET_DUMPABLE = 4
            libc.prctl(PR_SET_DUMPABLE, 0)
            logger.info("Process has been set to non-dumpable (prctl).")
        except Exception as e:
            logger.warning(f"Could not set process non-dumpable: {e}")
        try:
            libc = ctypes.CDLL("libc.so.6")
            MCL_CURRENT = 1
            MCL_FUTURE = 2
            res = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
            if res == 0:
                logger.info("Memory has been locked (mlockall).")
            else:
                logger.warning(
                    "mlockall failed. You may lack sufficient privileges.")
        except Exception as e:
            logger.warning(f"Could not lock memory: {e}")
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (100, 100))
            resource.setrlimit(resource.RLIMIT_NPROC, (50, 50))
            logger.info("Resource limits have been set.")
        except Exception as e:
            logger.warning(f"Could not set resource limits: {e}")
    else:
        logger.info(
            "Windows OS detected. Skipping Unix-specific hardening measures.")


def load_keys_from_stdin():
    """Read a JSON blob with private, public key, passphrase, and flag from stdin."""
    buf = ''
    while True:
        ch = sys.stdin.read(1)
        if ch == '':
            break  # EOF
        buf += ch
    try:
        d = json.loads(buf)
        return d
    except Exception as e:
        logger.error(f"Could not parse keys/passphrase blob from stdin: {e}")
        sys.exit(1)


def store_keys_in_memory(private_key_data, public_key_data, passphrase, keys_removed):
    # Keyring keys uniquely for this instance.
    KR_BASE = "phpgp/active"
    keyring.set_password(KR_BASE, "private_key", private_key_data)
    keyring.set_password(KR_BASE, "public_key", public_key_data)
    keyring.set_password(KR_BASE, "passphrase", passphrase)
    keyring.set_password(KR_BASE, "keys_removed", "1" if keys_removed else "0")


def get_key_from_memory(what):
    KR_BASE = "phpgp/active"
    return keyring.get_password(KR_BASE, what)


def start_server():
    apply_security_measures()

    # --- Step 1: Receive keys via stdin and store in RAM only ---
    d = load_keys_from_stdin()
    store_keys_in_memory(d.get("private_key", ""), d.get("public_key", ""),
                         d.get("passphrase", ""), d.get("keys_removed", True))

    private_key_data = get_key_from_memory("private_key")
    public_key_data = get_key_from_memory("public_key")
    passphrase = get_key_from_memory("passphrase")
    keys_removed_from_drive = get_key_from_memory("keys_removed") == "1"

    # Step 2: Parse PGP keys
    try:
        private_key, _ = PGPKey.from_blob(private_key_data)
        public_key, _ = PGPKey.from_blob(public_key_data)
    except Exception as e:
        logger.error(f"Cannot parse PGP keys: {e}")
        sys.exit(1)

    if private_key.is_protected:
        try:
            unlocked = private_key.unlock(passphrase)
            if unlocked:
                logger.info("Private key successfully unlocked.")
            else:
                logger.error("Failed to unlock private key.")
                sys.exit(1)
        except Exception as e:
            logger.error(f"Exception during unlocking key: {e}")
            sys.exit(1)
    else:
        logger.info("Private key was not protected by a passphrase.")

    # --- Step 3: Serve socket requests ---
    def handle_client_connection(client_socket, address=None):
        try:
            logger.info(f"Connection from {address}")
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
                encoded_data = request.get("data")
                if not encoded_data:
                    response["error"] = "No data provided for signing."
                else:
                    data_bytes = base64.b64decode(encoded_data)
                    message = PGPMessage.new(data_bytes, file=True)
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
                message_data = request.get("data")
                recipient_key_data = request.get("recipient_key")
                if not message_data or not recipient_key_data:
                    response["error"] = "Data or recipient_key not provided for encryption."
                else:
                    recipient_key, _ = PGPKey.from_blob(recipient_key_data)
                    message = PGPMessage.new(message_data)
                    encrypted_message = recipient_key.encrypt(message)
                    response["encrypted"] = str(encrypted_message)

            elif operation == "decrypt":
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

            elif operation in ("restore", "restore_keys"):
                if keys_removed_from_drive:
                    response["private_key_data"] = private_key_data
                    response["public_key_data"] = public_key_data
                else:
                    response["error"] = "Keys were not removed from the drive. Nothing to restore."
            else:
                response["error"] = f"Unsupported operation: {operation}"

            client_socket.sendall(json.dumps(response).encode())
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

    if platform.system() == "Windows":
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
    start_server()
