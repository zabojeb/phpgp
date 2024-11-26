#!/usr/bin/env python3

import os
import subprocess
import sys


def find_usb_drives():
    usb_drives = []

    try:
        for root, dirs, files in os.walk("/media"):
            if "physicgpg" in dirs:
                usb_drives.append(os.path.join(root, "physicgpg"))
    except:
        pass

    try:
        for root, dirs, files in os.walk("/Volumes"):
            if "physicgpg" in dirs:
                usb_drives.append(os.path.join(root, "physicgpg"))
    except:
        pass

    return usb_drives


def execute_script(script_path):
    if os.path.isfile(script_path) and os.access(script_path, os.X_OK):
        subprocess.run(script_path, check=True)
    else:
        print(f"Script {script_path} not found or does not have execution rights.")


def select_usb_drive(usb_drives):
    print("Found multiple devices with physicgpg:")
    for i, drive in enumerate(usb_drives, start=1):
        print(f"{i}: {drive}")
    choice = int(input("Enter device number: ")) - 1
    return usb_drives[choice]


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("mount", "dismount", "status"):
        print("Usage: phgpg mount | dismount | status")
        sys.exit(1)

    action = sys.argv[1]
    usb_drives = find_usb_drives()

    if not usb_drives:
        print("phGPG is not ready to act.")
        print("phGPG: Zero devices was found.")
        sys.exit(1)
    elif action == "status":
        print("phGPG is ready to act!")
        print(f"phGPG: {len(usb_drives)} devices was found: {usb_drives}")
        sys.exit(1)

    if len(usb_drives) > 1:
        selected_drive = select_usb_drive(usb_drives)
    else:
        selected_drive = usb_drives[0]

    script_path = os.path.join(selected_drive, action)
    execute_script(script_path)


if __name__ == "__main__":
    main()
