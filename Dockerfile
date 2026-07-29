FROM freebsd:15.0

RUN ASSUME_ALWAYS_YES=true pkg bootstrap -f && pkg update && pkg install -y python311 && pkg clean -a

CMD tail -f /dev/null