# phPGP

**phpgp** is a command-line utility designed for **secure storage and usage of PGP keys** on external drives (such as USB flash drives). The project provides a server component to handle cryptographic operations (sign, encrypt, decrypt) in memory, ensuring private keys do not remain on the host machine.

This README covers installation, usage, configuration, and other important details for working with **phpgp**.

---

## Table of Contents

- [phPGP](#phpgp)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Requirements](#requirements)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Usage](#usage)
    - [Mounting and Unmounting](#mounting-and-unmounting)
    - [Loading and Unloading Keys Locally](#loading-and-unloading-keys-locally)
  - [Cryptographic Operations](#cryptographic-operations)
    - [Signing Files](#signing-files)
    - [Encrypting and Decrypting Files](#encrypting-and-decrypting-files)
  - [How It Works](#how-it-works)
  - [Project Structure](#project-structure)
  - [Contributing](#contributing)
  - [License](#license)

---

## Features

- **Secure PGP key storage on external drives** (USB or similar)
- **Server-based cryptographic operations**: signing, encryption, and decryption happen in memory, reducing key exposure
- **Automatic passphrase prompt** when mounting the external drive.
- **Detachable signatures** or encryption of files using your private key, stored only on the external drive
- **Cross-platform**:
  - Windows uses a TCP socket (default port 65432)
  - macOS and Linux use a Unix Domain Socket (`/tmp/phpgp.sock` by default)
- **PID management in an OS-specific cache directory** (e.g., `%LOCALAPPDATA%\phpgp` on Windows, `~/Library/Caches/phpgp` on macOS, `~/.cache/phpgp` on Linux)

---

## Requirements

- **Python 3.7+** (recommended)
- **[GNUPG](https://gnupg.org/)** installed for local key imports (`load`, `unload`)
- **[psutil](https://pypi.org/project/psutil/)** for detecting removable drives
- **[Click](https://pypi.org/project/click/)** for building the CLI
- **[PGPy](https://pypi.org/project/PGPy/)** library for handling PGP operations in Python

---

## Installation

Simply install it via pip:

```bash
pip install phpgp
```

or via pipx (recommended):

```bash
pipx install phpgp
```

---

## Configuration

1. **Create or Obtain Your PGP Keys**:

   - For testing, you can generate keys with GnuPG:

     ```bash
     gpg --full-generate-key
     gpg --armor --export-secret-keys > private_key.asc
     gpg --armor --export > public_key.asc
     ```

   - Alternatively, you may have existing keys in `.asc` format.

2. **Configure an External Drive**:
   - Make sure your USB drive or removable storage is mounted.
   - Run:

     ```bash
     phpgp configure
     ```

   - This will prompt you for paths to your private and public keys and copy them to the drive (e.g., `X:\.phpgp\private` and `X:\.phpgp\public`).
   - You can choose to delete the keys from your local disk for extra security (which is recommended).

---

## Usage

Once installed, you have access to the `phpgp` command with various subcommands.

With phPGP you can either `mount` your USB or `load` keys from it.

When mounted, phPGP starts local server on your machine so you can do all PGP operations using this server and phpgp commands. This is **better** for security than just loading keys from USB.

Let's take a closer look at this.

### Mounting and Unmounting

- **Mount**:

  ```bash
  phpgp mount
  ```

  1. Select the external drive.
  2. Enter your passphrase to unlock your private key.
  3. The server starts in your terminal window.
  4. Optionally remove the key from the external drive.

- **Unmount**:

  ```bash
  phpgp unmount
  ```

  1. Reads the server PID from the OS cache directory (e.g., `~/.cache/phpgp/phpgp_server.pid`).
  2. Terminates the server process.
  3. Removes the PID file.

### Loading and Unloading Keys Locally

- **Load**:

  ```bash
  phpgp load
  ```

  Imports keys from your external drive into your local GPG instance, allowing you to use GnuPG commands locally with those keys.

- **Unload**:

  ```bash
  phpgp unload
  ```

  Removes the locally imported secret key from your GPG instance.

> [!NOTE]
> For greater security, you can set your computer to delete the private key automatically with this command when you disconnect the USB. You can do the same with key downloading for convenience.

## Cryptographic Operations

When you run the phPGP server via mount, you will want to perform operations using `phpgp` instead of `gpg`. This can be done with the appropriate commands: `phpgp sign`, `phpgp encrypt`, `phpgp decrypt`.

> [!IMPORTANT]
> These commands will only work when the server is started with `phpgp mount`.

### Signing Files

1. Make sure the server is running (`phpgp mount`).
2. Sign a file:

   ```bash
   phpgp sign path/to/file.txt
   ```

   - Reads `file.txt` in binary mode, base64-encodes it, sends it to the server.
   - A detached signature is saved to `file.txt.sig`.

3. Verify with GnuPG:

   ```bash
   gpg --verify file.txt.sig file.txt
   ```

### Encrypting and Decrypting Files

- **Encrypt**:

  ```bash
  phpgp encrypt path/to/file.txt path/to/recipient_public_key.asc
  ```

  - The encrypted data is saved to `file.txt.enc`.

- **Decrypt**:

  ```bash
  phpgp decrypt path/to/file.txt.enc
  ```

  - Decrypted data is saved to `file.txt.enc.dec`.

---

## How It Works

1. **Configuration**:
   - Creates a `.phpgp` folder on your external drive containing `private` and `public` folders with the appropriate keys.
2. **Mounting**:
   - Starts a background server (`phpgp.server`) with your private key loaded in memory.
   - For security, you can remove the key files from the USB drive after mounting (recommended).
3. **Server**:
   - Listens on a socket (TCP on Windows, Unix Domain Socket elsewhere).
   - Receives JSON requests for `sign`, `encrypt`, `decrypt`.
   - PGP operations happen in memory; the private key is **never** saved on local disk after mounting and **never** exposed until the `unmount` operation.
4. **Client Commands** (subcommands in `cli.py`):
   - Communicate with the server using JSON messages.
   - Return results (signatures, encrypted data, decrypted data).

---

## Project Structure

```
phpgp/
├── __init__.py            # Metadata
├── cli.py                 # Main CLI implemented with Click
├── server.py              # The server handling sign/encrypt/decrypt
└── utils.py               # Helper functions for drive selection & cache path
```

---

## Contributing

There is some issues now, feel free to fix them!

1. **Fork** the repository on GitHub.
2. **Create a Feature Branch** from `main`.
3. **Implement** your feature or bug fix.
4. **Add Tests** where and if applicable.
5. **Open a Pull Request** describing your changes.

---

## License

phpgp is licensed under the GNU General Public License v3.0.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

---

**Enjoy secure and convenient PGP key usage with phPGP!**
