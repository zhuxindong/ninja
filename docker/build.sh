#!/bin/bash

: ${tag=latest}

cd docker
docker buildx build --platform linux/amd64 \
    --tag zhuxindong/ninja:$tag \
    --tag zhuxindong/ninja:latest \
    --build-arg VERSION=$tag --push .

cd render
docker buildx build -t gngpp/ninja:warp -t ghcr.io/gngpp/ninja:warp . --push
cd -
cd -