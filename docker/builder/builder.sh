#!/bin/bash

declare -A map

map["x86_64-unknown-linux-musl"]="x86_64-musl"
map["aarch64-unknown-linux-musl"]="aarch64-musl"
map["armv7-unknown-linux-musleabi"]="armv7-musleabi"
map["armv7-unknown-linux-musleabihf"]="armv7-musleabihf"
map["arm-unknown-linux-musleabi"]="arm-musleabi"
map["arm-unknown-linux-musleabihf"]="arm-musleabihf"
map["armv5te-unknown-linux-musleabi"]="armv5te-musleabi"
map["i686-unknown-linux-musl"]="i686-musl"
map["mips-unknown-linux-musl"]="mips-musl"
map["mipsel-unknown-linux-musl"]="mipsel-musl"
map["mips64-unknown-linux-muslabi64"]="mips64-muslabi64"
map["mips64el-unknown-linux-muslabi64"]="mips64el-muslabi64"

for key in "${!map[@]}"; do
  docker buildx build --platform linux/amd64,linux/arm64 \
    --tag gngpp/opengpt-builder:"$key" \
    --tag ghcr.io/gngpp/opengpt-builder:"$key" \
    --build-arg BASE_IMAGE=ghcr.io/messense/rust-musl-cross:"${map[$key]}" . --push 
done