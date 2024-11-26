#!/usr/bin/env sh

fetch https://github.com/zabojeb/phgpg/blob/main/phgpg.py
chmod +x phgpg.py
mv phgpp.py /usr/local/bin/phgpg

echo "phgpg succesfully installed!"
