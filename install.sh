#!/usr/bin/env sh

fetch https://raw.githubusercontent.com/zabojeb/phgpg/refs/heads/main/phgpg.py
sudo chmod +x phgpg.py
sudo mv phgpp.py /usr/local/bin/phgpg

echo "phgpg succesfully installed!"
