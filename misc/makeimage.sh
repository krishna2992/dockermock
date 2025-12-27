#!/bin/sh

set -eu -o pipefail

OCI_IMAGE_URL=${OCI_IMAGE_URL:-https://download.freebsd.org/releases/OCI-IMAGES/14.2-RELEASE/amd64/Latest/FreeBSD-14.2-RELEASE-amd64-container-image-minimal.txz}

if [ $# != 1 ]
then
  echo Usage:  ociimagextract.sh /path/to/output/directory
  echo         Default OCI image: $OCI_IMAGE_URL
  echo         To use a different image set OCI_IMAGE_URL:
  echo         OCI_IMAGE_URL=https://other-image-url ociimagextract.sh /path/to/output/directory
  exit 1
fi

TARGET=$1

which jq
if [ $? != 0 ]
then
  echo Could not find jq command
  echo You can install jq using "pkg install jq"
  exit 1
fi

mkdir -p $TARGET
DIR=`mktemp --directory`
fetch -q -o - $OCI_IMAGE_URL | tar -xzvpf - -C$DIR
TOPDIGEST=`cat $DIR/index.json | jq -r .manifests[0].digest | tr ':' '/'`
DIGESTS=`cat $DIR/blobs/$TOPDIGEST | jq -r '.layers[] | .digest' | tr ':' '/'`

for DIGEST in $DIGESTS
do
 cat $DIR/blobs/$DIGEST | tar -xzvpf - -C$TARGET
done

echo jail root filesystem directory created at $TARGET
