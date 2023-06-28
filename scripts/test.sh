#!/bin/bash
#
# test.sh
#
# Test all the library build configurations
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
        cd target/$i
        make test ARGS=-j8
    )
done
