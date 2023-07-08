#!/bin/bash

: ${tag=latest}

cd docker
docker buildx build --platform linux/amd64,linux/arm64/v8,linux/arm/v7,linux/arm/v6 \
    --tag ghcr.io/gngpp/opengpt:$tag \
    --tag ghcr.io/gngpp/opengpt:latest \
    --tag gngpp/opengpt:$tag \
    --tag gngpp/opengpt:latest \
    --build-arg VERSION=$tag --push .
cd -