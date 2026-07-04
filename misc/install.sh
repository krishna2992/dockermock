# !/bin/sh

#  First install pkg requirments
ASSUME_ALWAYS=yes sudo pkg install py311-sqlite3 libpfctl py311-libzfs

# Create a venv for dependencies installation
python -m venv env
. env/bin/activate

./env/bin/python -m ensurepip
./env/bin/python -m pip install -r misc/requirments.txt

deactivate
