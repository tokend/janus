#!/bin/sh

set -ex

docker build -t test -f test.dockerfile .
docker run test ./...
