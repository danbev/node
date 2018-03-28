#!/bin/bash
# This script downloads the specified OpenSSL version and replaces
# the existing source code and commit the changes.
SCRIPTSDIR="`dirname \"$0\"`"

if [ -z "$1" ]; then
  echo "Usage: update <version>"
  exit 1
fi

version=$1
name=openssl-${version}
tar_name=${name}.tar.gz

pushd ${SCRIPTSDIR}/..
wget https://www.openssl.org/source/${tar_name}

rm -rf openssl
tar zxf $tar_name
mv ${name} openssl

git add --all openssl
git commit openssl -F- <<EOF
deps: upgrade openssl sources to $version

This replaces all sources of $tar_name into
deps/openssl/openssl
EOF

rm $tar_name
popd

