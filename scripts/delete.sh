#!/bin/bash
#
# delete.sh
#
# Delete build files
#
# @author Kealan McCusker <kealanmccusker@gmail.com>
# ------------------------------------------------------------------------------

# NOTES:

function delete()
{
  echo "remove build files"
  rm -rf target
  rm -rf build
  rm -rf coverage
}

delete
