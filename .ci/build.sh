#!/bin/sh

docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
docker build -t $GL_IMAGE_NAME
docker push $GL_IMAGE_NAME
