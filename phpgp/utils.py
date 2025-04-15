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
import psutil
import click
import platform


def find_external_drives():
    partitions = psutil.disk_partitions()
    external_drives = [
        p.mountpoint for p in partitions if 'removable' in p.opts or 'usb' in p.opts or p.mountpoint.startswith("/Volumes/")
    ]
    return external_drives


def select_drive():
    """
    Prompts the user to select a removable (USB) drive from the list of available external drives.
    Exits the program if no external drives are found.

    :return: The mountpoint of the selected external drive.
    """
    external_drives = find_external_drives()

    if not external_drives:
        click.echo("No external drives found.")
        exit(1)

    click.echo("Select a drive:")
    for idx, drive in enumerate(external_drives, start=1):
        click.echo(f"{idx}. {drive}")

    choice = click.prompt("Enter choice", type=int)

    if choice < 1 or choice > len(external_drives):
        click.echo("Invalid choice.")
        exit(1)

    return external_drives[choice - 1]


def get_cache_dir():
    """
    Returns the appropriate cache directory based on the operating system.
    Creates the directory if it does not exist.

    :return: Path to the cache directory.
    """
    home = os.path.expanduser("~")
    system = platform.system()

    if system == "Windows":
        cache_dir = os.path.join(os.getenv('LOCALAPPDATA'), 'phpgp')
    elif system == "Darwin":
        cache_dir = os.path.join(home, 'Library', 'Caches', 'phpgp')
    else:
        # Assume Linux or other Unix-like
        cache_dir = os.path.join(
            os.getenv('XDG_CACHE_HOME', os.path.join(home, '.cache')), 'phpgp')

    os.makedirs(cache_dir, exist_ok=True)
    return cache_dir


def get_pid_file_path():
    """
    Returns the full path to the PID file in the cache directory.

    :return: Full path to 'phpgp_server.pid' in the cache directory.
    """
    cache_dir = get_cache_dir()
    return os.path.join(cache_dir, 'phpgp_server.pid')
