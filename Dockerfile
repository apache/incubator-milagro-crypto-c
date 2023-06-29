# Dockerfile
#
# Ubuntu 22.04 
#
# @author  Kealan McCusker <kealanmccusker@gmail.com>
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# NOTES:
#
# Create the image:
#     docker build -t libamcl .
#
# Run tests:
#     docker run --rm libamcl ./scripts/test.sh
#
# Generate coverage figures:
#     CONTAINER_ID=$(docker run -d libamcl ./scripts/coverage.sh)
#     docker logs $CONTAINER_ID
#     docker cp ${CONTAINER_ID}:"/root/target/Coverage/coverage" ./
#     docker rm -f ${CONTAINER_ID} || true
#
# To login to container:
#     docker run -it --rm libamcl bash
# ------------------------------------------------------------------------------

FROM ubuntu:22.04

LABEL maintainer="kealanmccusker@gmail.com"

WORKDIR /root

ENV DEBIAN_FRONTEND=noninteractive

ENV LD_LIBRARY_PATH=/usr/local/lib:./

ENV ASAN_OPTIONS=verify_asan_link_order=0

RUN echo "## Start building" \
    && echo "## Update and install packages" \
    && apt-get -y update \
    && apt-get install -y --no-install-recommends \
        build-essential \
	cmake \
	doxygen \
	lcov \
	python3-dev \
	python3-pip \
	wget \
	git \
	libffi-dev \
    && echo "## Done"

RUN pip3 install cffi

ADD . /root

RUN ./scripts/build.sh

RUN ./scripts/test.sh


