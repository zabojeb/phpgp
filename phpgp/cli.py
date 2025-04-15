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
import shutil
import socket
import subprocess
import platform
from getpass import getpass
import threading

import click
import gnupg
import psutil
from pgpy import PGPKey, PGPMessage
import keyring
import tempfile

from .utils import select_drive, get_pid_file_path, get_cache_dir, find_external_drives
from .server import start_server

if platform.system() == "Windows":
    HOST = "127.0.0.1"
    PORT = 65432
else:
    SOCKET_PATH = "/tmp/phpgp.sock"


def start_phpgp_server_with_stdin(private_key_data, public_key_data, passphrase, keys_removed_from_drive):
    """
    Start the phpgp.server as subprocess, passing the keys and passphrase via stdin.
    """
    import json
    import sys
    import platform

    keyblob = json.dumps({
        "private_key": private_key_data,
        "public_key": public_key_data,
        "passphrase": passphrase,
        "keys_removed": bool(keys_removed_from_drive),
    })
    if platform.system() == "Windows":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        proc = subprocess.Popen([sys.executable, "-m", "phpgp.server"],
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                startupinfo=startupinfo,
                                text=True)
    else:
        proc = subprocess.Popen([sys.executable, "-m", "phpgp.server"],
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True)
    proc.stdin.write(keyblob)
    proc.stdin.flush()
    proc.stdin.close()
    return proc


@click.group()
def cli():
    """
    The main CLI for phpgp — a utility to securely store and use PGP keys
    on external drives (USB, etc). It interacts with a background server
    that handles cryptographic operations (sign, encrypt, decrypt).
    """
    pass


@cli.command()
def configure():
    """
    Configure an external drive for use with phpgp. Copies the user's
    private/public keys to the drive and optionally deletes them
    from the local machine.
    """
    drive = select_drive()
    click.echo(f"Selected drive: {drive}")

    private_key_path = click.prompt(
        "Enter full path to your private key", type=click.Path(exists=True)
    )
    public_key_path = click.prompt(
        "Enter full path to your public key", type=click.Path(exists=True)
    )

    phpgp_path = os.path.join(drive, ".phpgp")
    private_path = os.path.join(phpgp_path, "private")
    public_path = os.path.join(phpgp_path, "public")

    os.makedirs(private_path, exist_ok=True)
    os.makedirs(public_path, exist_ok=True)

    shutil.copy(private_key_path, private_path)
    shutil.copy(public_key_path, public_path)

    click.echo(f"Keys copied to {phpgp_path}")

    delete = click.confirm(
        "Delete original key files from the computer?", default=False)
    if delete:
        os.remove(private_key_path)
        os.remove(public_key_path)
        click.echo("Original keys deleted.")
    else:
        click.echo("Original keys retained.")


@cli.command()
def status():
    """
    Checks the status of connected external drives, indicating whether
    each is ready to mount (contains .phpgp) or ready to configure.
    """
    external_drives = find_external_drives()

    if not external_drives:
        click.echo("No external drives found.")
        return

    for drive in external_drives:
        phpgp_path = os.path.join(drive, ".phpgp")
        if os.path.exists(phpgp_path):
            status = "Ready to mount."
        else:
            status = "Ready to configure."
        click.echo(f"{drive}: {status}")


@cli.command()
def mount():
    """
    Mount a configured external drive, and optionally remove the key files
    from the drive. If removed, the server keeps them in memory, so
    we can restore them on unmount.
    """
    drive = select_drive()
    phpgp_path = os.path.join(drive, ".phpgp")

    if not os.path.exists(phpgp_path):
        click.echo(
            "Selected drive is not configured. Please run 'phpgp configure' first.")
        sys.exit(1)

    private_key_path = os.path.join(phpgp_path, "private", "private_key.asc")
    public_key_path = os.path.join(phpgp_path, "public", "public_key.asc")

    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        click.echo("Key files not found on the drive.")
        sys.exit(1)

    with open(private_key_path, "r") as f:
        private_key_data = f.read()
    with open(public_key_path, "r") as f:
        public_key_data = f.read()

    password = getpass("Enter passphrase for your private key: ")

    env = os.environ.copy()
    env.update({
        "PRIVATE_KEY": private_key_data,
        "PUBLIC_KEY": public_key_data,
        "PRIVATE_KEY_PASSPHRASE": password
    })

    startupinfo = None
    if platform.system() == "Windows":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE

    remove_keys = click.confirm(
        "Delete key files from the external drive?", default=True)
    keys_removed_flag = bool(remove_keys)

    server_process = start_phpgp_server_with_stdin(
        private_key_data, public_key_data, password, keys_removed_flag
    )
    click.echo("phpgp server started.")

    pid_file = get_pid_file_path()
    with open(pid_file, "w") as f:
        f.write(str(server_process.pid))

    def stream_output(process):
        for line in iter(process.stdout.readline, ""):
            click.echo(line, nl=False)
        for line in iter(process.stderr.readline, ""):
            click.echo(line, nl=False, err=True)

    output_thread = threading.Thread(
        target=stream_output, args=(server_process,))
    output_thread.daemon = True
    output_thread.start()

    if remove_keys:
        os.remove(private_key_path)
        os.remove(public_key_path)
        click.echo("Keys removed from the external drive.")
    else:
        click.echo("Keys retained on the external drive.")


@cli.command()
def load():
    """
    Imports the keys from a configured external drive into the local GPG instance.
    """
    drive = select_drive()
    phpgp_path = os.path.join(drive, ".phpgp")

    if not os.path.exists(phpgp_path):
        click.echo("Selected drive is not configured.")
        sys.exit(1)

    private_key_path = os.path.join(phpgp_path, "private", "private_key.asc")
    public_key_path = os.path.join(phpgp_path, "public", "public_key.asc")

    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        click.echo("Key files not found on the drive.")
        sys.exit(1)

    gpg = gnupg.GPG()

    with open(public_key_path, "r") as f:
        public_key_data = f.read()

    with open(private_key_path, "r") as f:
        private_key_data = f.read()

    import_result = gpg.import_keys(public_key_data)
    if import_result.count == 0:
        click.echo("Failed to import public key.")
    else:
        click.echo("Public key imported successfully.")

    import_result = gpg.import_keys(private_key_data)
    if import_result.count == 0:
        click.echo("Failed to import private key.")
    else:
        click.echo("Private key imported successfully.")

    for fingerprint in import_result.fingerprints:
        gpg.trust_keys(fingerprint, "TRUST_ULTIMATE")
        click.echo(f"Key {fingerprint} trusted.")


@cli.command()
def unload():
    """
    Removes the locally imported secret key from the GPG instance, if it exists.
    """
    import gnupg
    from getpass import getpass

    gpg = gnupg.GPG()
    keys = gpg.list_keys(secret=True)
    if not keys:
        click.echo("No keys found in GPG.")
        return

    for key in keys:
        fingerprint = key["fingerprint"]
        confirm = click.confirm(
            f"Do you want to delete key {fingerprint}?", default=False)
        if confirm:
            passphrase = getpass("Enter passphrase for the key: ")
            result = gpg.delete_keys(
                fingerprint, secret=True, passphrase=passphrase)
            if result.status == "ok":
                click.echo(f"Key {fingerprint} deleted successfully.")
            else:
                click.echo(
                    f"Failed to delete key {fingerprint}: {result.status}", err=True)
                if result.stderr:
                    click.echo(f"Error: {result.stderr}", err=True)


@cli.command()
@click.argument("file", type=click.Path(exists=True))
def sign(file):
    """
    Signs a file through the server. Reads the file in binary mode, encodes
    in base64, then sends it to the phpgp server for signing. The resulting
    detached signature is stored as <file>.sig.
    """
    if platform.system() == "Windows":
        HOST = "127.0.0.1"
        PORT = 65432
    else:
        SOCKET_PATH = "/tmp/phpgp.sock"

    with open(file, "rb") as f:
        data = f.read()

    encoded_data = base64.b64encode(data).decode("utf-8")

    request = {
        "operation": "sign",
        "data": encoded_data
    }
    request_json = json.dumps(request)

    try:
        if platform.system() == "Windows":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((HOST, PORT))
                client_socket.sendall(request_json.encode())

                response_data = client_socket.recv(65536).decode()
                response = json.loads(response_data)

                if "signature" in response:
                    signature_file = f"{file}.sig"
                    with open(signature_file, "w") as f_sig:
                        f_sig.write(response["signature"])
                    click.echo(f"Signature saved to {signature_file}")
                else:
                    click.echo(response.get(
                        "error", "Unknown error occurred."), err=True)
                    sys.exit(1)
        else:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client_socket:
                client_socket.connect(SOCKET_PATH)
                client_socket.sendall(request_json.encode())

                response_data = client_socket.recv(65536).decode()
                response = json.loads(response_data)

                if "signature" in response:
                    signature_file = f"{file}.sig"
                    with open(signature_file, "w") as f_sig:
                        f_sig.write(response["signature"])
                    click.echo(f"Signature saved to {signature_file}")
                else:
                    click.echo(response.get(
                        "error", "Unknown error occurred."), err=True)
                    sys.exit(1)
    except Exception as e:
        click.echo(f"Error connecting to phpgp server: {str(e)}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.argument("recipient_email")
def encrypt(file, recipient_email):
    """
    Encrypts a file for the specified recipient PGP key through the server.
    """
    if platform.system() == "Windows":
        HOST = "127.0.0.1"
        PORT = 65432
    else:
        SOCKET_PATH = "/tmp/phpgp.sock"

    with open(file, "r") as f:
        data = f.read()

    request = {
        "operation": "encrypt",
        "data": data,
        "recipient_email": recipient_email
    }
    request_json = json.dumps(request)

    try:
        if platform.system() == "Windows":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((HOST, PORT))
                client_socket.sendall(request_json.encode())

                response_data = client_socket.recv(65536).decode()
                response = json.loads(response_data)

                if "encrypted" in response:
                    encrypted_file = f"{file}.enc"
                    with open(encrypted_file, "w") as f_enc:
                        f_enc.write(response["encrypted"])
                    click.echo(f"File encrypted and saved as {encrypted_file}")
                else:
                    click.echo(response.get(
                        "error", "Unknown error occurred."), err=True)
                    sys.exit(1)
        else:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client_socket:
                client_socket.connect(SOCKET_PATH)
                client_socket.sendall(request_json.encode())

                response_data = client_socket.recv(65536).decode()
                response = json.loads(response_data)

                if "encrypted" in response:
                    encrypted_file = f"{file}.enc"
                    with open(encrypted_file, "w") as f_enc:
                        f_enc.write(response["encrypted"])
                    click.echo(f"File encrypted and saved as {encrypted_file}")
                else:
                    click.echo(response.get(
                        "error", "Unknown error occurred."), err=True)
                    sys.exit(1)
    except Exception as e:
        click.echo(f"Error connecting to phpgp server: {str(e)}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("file", type=click.Path(exists=True))
def decrypt(file):
    """
    Decrypts a file through the server. The server uses the private key
    to decrypt. The resulting plaintext is saved as <file>.dec.
    """
    if platform.system() == "Windows":
        HOST = "127.0.0.1"
        PORT = 65432
    else:
        SOCKET_PATH = "/tmp/phpgp.sock"

    with open(file, "r") as f:
        encrypted_data = f.read()

    request = {
        "operation": "decrypt",
        "data": encrypted_data
    }
    request_json = json.dumps(request)

    try:
        if platform.system() == "Windows":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((HOST, PORT))
                client_socket.sendall(request_json.encode())

                response_data = client_socket.recv(65536).decode()
                response = json.loads(response_data)

                if "decrypted" in response:
                    decrypted_file = f"{file}.dec"
                    with open(decrypted_file, "w") as f_dec:
                        f_dec.write(response["decrypted"])
                    click.echo(f"File decrypted and saved as {decrypted_file}")
                else:
                    click.echo(response.get(
                        "error", "Unknown error occurred."), err=True)
                    sys.exit(1)
        else:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client_socket:
                client_socket.connect(SOCKET_PATH)
                client_socket.sendall(request_json.encode())

                response_data = client_socket.recv(65536).decode()
                response = json.loads(response_data)

                if "decrypted" in response:
                    decrypted_file = f"{file}.dec"
                    with open(decrypted_file, "w") as f_dec:
                        f_dec.write(response["decrypted"])
                    click.echo(f"File decrypted and saved as {decrypted_file}")
                else:
                    click.echo(response.get(
                        "error", "Unknown error occurred."), err=True)
                    sys.exit(1)
    except Exception as e:
        click.echo(f"Error connecting to phpgp server: {str(e)}", err=True)
        sys.exit(1)


@cli.command()
def unmount():
    """
    Unmount the phpgp server by terminating its process using the PID stored in the cache directory.
    """

    # 1) Attempt to restore keys from the server
    drive = select_drive()  # TODO: make server memorize the drive
    phpgp_path = os.path.join(drive, ".phpgp")
    private_dir = os.path.join(phpgp_path, "private")
    public_dir = os.path.join(phpgp_path, "public")
    os.makedirs(private_dir, exist_ok=True)
    os.makedirs(public_dir, exist_ok=True)

    if platform.system() == "Windows":
        HOST = "127.0.0.1"
        PORT = 65432
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((HOST, PORT))
                request_json = json.dumps(
                    {"operation": "restore"}).encode()
                client_socket.sendall(request_json)
                response_data = client_socket.recv(65536).decode()
                resp = json.loads(response_data)

                if "private_key_data" in resp and "public_key_data" in resp:
                    private_file = os.path.join(private_dir, "private_key.asc")
                    public_file = os.path.join(public_dir, "public_key.asc")
                    with open(private_file, "w") as f_pk:
                        f_pk.write(resp["private_key_data"])
                    with open(public_file, "w") as f_pub:
                        f_pub.write(resp["public_key_data"])
                    click.echo(
                        "Private/public keys restored to the external drive.")
                elif "error" in resp:
                    click.echo(f"Cannot restore keys: {resp['error']}")
        except Exception as e:
            click.echo(f"Error requesting 'restore': {e}")
    else:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client_socket:
                client_socket.connect(SOCKET_PATH)
                request_json = json.dumps(
                    {"operation": "restore_keys"}).encode()
                client_socket.sendall(request_json)
                response_data = client_socket.recv(65536).decode()
                resp = json.loads(response_data)

                if "private_key_data" in resp and "public_key_data" in resp:
                    private_file = os.path.join(private_dir, "private_key.asc")
                    public_file = os.path.join(public_dir, "public_key.asc")
                    with open(private_file, "w") as f_pk:
                        f_pk.write(resp["private_key_data"])
                    with open(public_file, "w") as f_pub:
                        f_pub.write(resp["public_key_data"])
                    click.echo(
                        "Private/public keys restored to the external drive.")
                elif "error" in resp:
                    click.echo(f"Cannot restore keys: {resp['error']}")
        except Exception as e:
            click.echo(f"Error requesting 'restore_keys': {e}")

    # 2) Kill the server
    pid_file = get_pid_file_path()
    if os.path.exists(pid_file):
        with open(pid_file, "r") as f:
            try:
                pid = int(f.read())
            except ValueError:
                click.echo("Invalid PID in PID file.")
                sys.exit(1)

        try:
            proc = psutil.Process(pid)
            if "python" in proc.name().lower():
                proc.terminate()
                proc.wait(timeout=5)
                click.echo("phpgp server stopped.")
            else:
                click.echo(
                    "Process with PID does not seem to be phpgp server.")
        except psutil.NoSuchProcess:
            click.echo("phpgp server is not running.")
        except psutil.TimeoutExpired:
            click.echo("Failed to terminate phpgp server.")
        except Exception as e:
            click.echo(f"Error stopping server: {e}", err=True)

        try:
            os.remove(pid_file)
        except Exception as e:
            click.echo(f"Error removing PID file: {e}", err=True)
    else:
        click.echo(
            "phpgp server PID file not found. Server might not be running.")


if __name__ == "__main__":
    cli()
