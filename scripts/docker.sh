#!/bin/bash
#
# docker.sh
#
# Build and test code in docker
#
# @author Kealan McCusker <kealanmccusker@gmail.com>
# ------------------------------------------------------------------------------

# NOTES:

set -Cue -o pipefail

SCRIPT_HOME="$(cd "$(dirname "${0}")" && pwd)"
cd "$SCRIPT_HOME/.."

usage()
{
cat << EOF
usage: $0 options

OPTIONS:
   -b      Build docker image
   -t      Run tests
   -c      Get coverage figures
   -i      Login to containerAdd docker images to microk8s
   -k      Stop and remove containers
   -h      Print usage

EXAMPLE:

   ./docker.sh -b -t -c -i -k -h
EOF
}

function build()
{
  echo "echo docker build -t libamcl ."
  docker build -t libamcl .
}

function test()
{
  echo "docker run --cap-add SYS_PTRACE --rm libamcl"
  docker run --cap-add SYS_PTRACE --rm libamcl
}

function coverage()
{
  echo "docker run --cap-add SYS_PTRACE libamcl ./scripts/coverage.sh"
  docker run --cap-add SYS_PTRACE libamcl ./scripts/coverage.sh
}

function login()
{
  echo "docker run -it --rm libamcl bash"
  docker run -it --rm libamcl bash
}

function kill()
{
    CONTAINER_ID=`docker ps -a | grep libamcl | cut -c1-12`

    if [ "${CONTAINER_ID}" ];
    then
	echo "docker stop $CONTAINER_ID"
	docker stop "$CONTAINER_ID"
	docker rm  "$CONTAINER_ID"
    fi
}

while getopts "btcikh" OPTION
do
     case $OPTION in
         b)
             build
             ;;
         t)
	     test
             ;;
         c)
             coverage
             ;;
         i)
             login
             ;;
         k)
             kill
             ;;
         h)
             usage
             exit 1
             ;;
         :)
             echo "Missing required argument" 1>&2
             usage
             exit 1
             ;;
         \?)
             echo "Invalid option: -$OPTARG" 1>&2
             usage
             exit 1
             ;;
     esac
done

if [ "$1" == "" ]
then
    usage
    exit 1
fi
