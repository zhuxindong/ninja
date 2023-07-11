#!/bin/bash

declare -A map

map["x86_64-unknown-linux-musl"]="ghcr.io/messense/rust-musl-cross:x86_64-musl"
map["aarch64-unknown-linux-musl"]="ghcr.io/messense/rust-musl-cross:aarch64-musl"
map["armv7-unknown-linux-musleabi"]="ghcr.io/messense/rust-musl-cross:armv7-musleabi"
map["armv7-unknown-linux-musleabihf"]="ghcr.io/messense/rust-musl-cross:armv7-musleabihf"
map["arm-unknown-linux-musleabi"]="ghcr.io/messense/rust-musl-cross:arm-musleabi"
map["arm-unknown-linux-musleabihf"]="ghcr.io/messense/rust-musl-cross:arm-musleabihf"
map["armv5te-unknown-linux-musleabi"]="ghcr.io/messense/rust-musl-cross:armv5te-musleabi"
map["x86_64-pc-windows-msvc"]="ghcr.io/messense/cargo-xwin:latest"

for key in "${!map[@]}"; do
  docker buildx build --platform linux/amd64,linux/arm64 \
    --tag gngpp/opengpt-builder:"$key" \
    --tag ghcr.io/gngpp/opengpt-builder:"$key" \
    --build-arg BASE_IMAGE="${map[$key]}" . --push 
done