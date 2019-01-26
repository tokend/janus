#!/bin/sh

set -ex

docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
docker build -t $GITLAB_IMAGE_NAME .
docker push $GITLAB_IMAGE_NAME
