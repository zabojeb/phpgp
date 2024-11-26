#!/usr/bin/env sh

curl https://raw.githubusercontent.com/zabojeb/phgpg/refs/heads/main/phgpg.py >phgpg.py
chmod +x phgpg.py
mv phgpp.py /usr/local/bin/phgpg

echo "phgpg succesfully installed!"
