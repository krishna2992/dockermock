# !/bin/sh


if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This program must be run as root." >&2
    echo "Please run it again with sudo or as the root user." >&2
    exec sudo "$0" "$@"
fi

. env/bin/activate


LOGFILE="server.log"
daemon -o "$LOGFILE" -p server.pid python server.py

echo "Server started."
echo "PID: $!"
echo "Log: $LOGFILE"