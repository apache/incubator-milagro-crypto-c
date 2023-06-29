#!/bin/bash
#
# format.sh
#
# Format the source code
#
# @author Kealan McCusker <kealanmccusker@gmail.com>
# ------------------------------------------------------------------------------

# NOTES:

astyle --style=allman --recursive --suffix=none '*.c'
astyle --style=allman --recursive --suffix=none '*.c.in'
astyle --style=allman --recursive --suffix=none '*.h'
