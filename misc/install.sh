# !/bin/sh

#  First install pkg requirments
ASSUME_ALWAYS=yes sudo pkg install py311-sqlite3 libpfctl py311-libzfs unionfs-fusefs

NEEDS_REBOOT=0
# Set rctl enable in loader
LOADER_CONF="/boot/loader.conf"
if [ "$(sysctl -n kern.racct.enable 2>/dev/null)" != "1" ]; then
    if grep -Eq '^[[:space:]]*kern\.racct\.enable[[:space:]]*=' "$LOADER_CONF"; then
        sed -i '' \
            -E 's|^[[:space:]]*kern\.racct\.enable[[:space:]]*=.*$|kern.racct.enable=1|' \
            "$LOADER_CONF"
    else
        echo "kern.racct.enable=1" >> "$LOADER_CONF"
    fi
    NEEDS_REBOOT=1
else
    echo "RACT Already enabled"
fi

# Create a venv for dependencies installation
python -m venv --system-site-packages env
. env/bin/activate

./env/bin/python -m ensurepip
./env/bin/python -m pip install -r misc/requirments.txt

deactivate

if [ "$NEEDS_REBOOT" -eq 1 ]; then
    echo "A reboot is required for the change to take effect."
fi