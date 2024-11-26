#!/usr/bin/env sh

curl https://raw.githubusercontent.com/zabojeb/phgpg/refs/heads/main/phgpg.py >phgpg.py
sudo chmod +x phgpg.py
sudo mv phgpg.py /usr/local/bin/phgpg

echo "phgpg succesfully installed!"
