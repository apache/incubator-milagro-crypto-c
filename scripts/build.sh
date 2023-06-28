#!/bin/bash
#
# build.sh
#
# Build AMCL
#
# @author Kealan McCusker <kealanmccusker@gmail.com>
# ------------------------------------------------------------------------------

# NOTES:

set -Cue -o pipefail

PROJECT_HOME="$(cd "$(dirname "${0}")/.." && pwd)"
cd "$PROJECT_HOME"

declare -a arr=("Release" "Debug" "Coverage" "ASan")

for i in "${arr[@]}"
do
    (
	echo "$i"
        rm -rf target/$i
        mkdir -p target/$i
        cd target/$i

        cmake -D CMAKE_BUILD_TYPE=$i \
              -D BUILD_SHARED_LIBS=ON \
              -D DEBUG_NORM=OFF \
              -D AMCL_CHUNK=64 \
              -D AMCL_CURVE="BLS381,SECP256K1,ED25519" \
              -D AMCL_RSA="2048,4096" \
              -D BUILD_PAILLIER=ON \
              -D BUILD_PYTHON=ON \
              -D BUILD_BLS=ON \
              -D BUILD_BLS_IETF=ON \
              -D BUILD_WCC=OFF \
              -D BUILD_MPIN=ON \
              -D BUILD_X509=OFF \
              -D CMAKE_INSTALL_PREFIX=/usr/local ../..

        make
  )
done
