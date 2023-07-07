#!/bin/bash

: ${tag=latest}

cd docker
docker buildx build --platform linux/amd64,linux/arm64 \
    --tag ghcr.io/gngpp/opengpt:$tag \
    --tag gngpp/opengpt:$tag \
    --tag gngpp/opengpt:latest \
    --tag ghcr.io/gngpp/opengpt:latest \
    --build-arg VERSION=$tag --push .
cd -