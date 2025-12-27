# !/bin/sh
python -m venv env
source env/bin/activate
python -m pip install -r misc/requirments.txt
pkg install py311-sqlite3 libpfctl
