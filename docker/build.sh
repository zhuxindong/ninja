#!/bin/bash

: ${tag=latest}

cd docker
docker buildx build --platform linux/amd64 \
    --tag zhuxindong/ninja:$tag \
    --tag zhuxindong/ninja:latest \
    --build-arg VERSION=$tag --push .
