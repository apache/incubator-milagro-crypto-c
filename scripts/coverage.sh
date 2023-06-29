#!/bin/bash
#
# coverage.sh
#
# Generate coverage figures
#
# @author Kealan McCusker <kealanmccusker@gmail.com>
# ------------------------------------------------------------------------------

# NOTES:

CURRENTDIR=${PWD}

function coverage()
{
  echo "coverage"
  cd $CURRENTDIR/target/Coverage
  mkdir coverage
  lcov --capture --initial --directory . --output-file coverage/libamcl.info
  lcov --no-checksum --directory . --capture --output-file coverage/libamcl.info
  lcov --remove coverage/libamcl.info "*/test_*" --output-file coverage/libamcl.info
  genhtml -o coverage -t "AMCL Test Coverage" coverage/libamcl.info
}

coverage
