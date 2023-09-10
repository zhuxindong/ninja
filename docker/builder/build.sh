#!/bin/bash

declare -A map

map["x86_64-unknown-linux-musl"]="ghcr.io/gngpp/rust-musl-cross:x86_64-musl"
map["aarch64-unknown-linux-musl"]="ghcr.io/gngpp/rust-musl-cross:aarch64-musl"
map["armv7-unknown-linux-musleabi"]="ghcr.io/gngpp/rust-musl-cross:armv7-musleabi"
map["armv7-unknown-linux-musleabihf"]="ghcr.io/gngpp/rust-musl-cross:armv7-musleabihf"
map["arm-unknown-linux-musleabi"]="ghcr.io/gngpp/rust-musl-cross:arm-musleabi"
map["arm-unknown-linux-musleabihf"]="ghcr.io/gngpp/rust-musl-cross:arm-musleabihf"
map["armv5te-unknown-linux-musleabi"]="ghcr.io/gngpp/rust-musl-cross:armv5te-musleabi"
map["x86_64-pc-windows-msvc"]="ghcr.io/gngpp/cargo-xwin:latest"

for key in "${!map[@]}"; do
  docker pull "${map[$key]}"
  docker buildx build --platform linux/amd64,linux/arm64 \
    --tag gngpp/ninja-builder:"$key" \
    --tag ghcr.io/gngpp/ninja-builder:"$key" \
    --build-arg BASE_IMAGE="${map[$key]}" . --push
  echo "Build complete for $key"
  docker rmi ghcr.io/gngpp/ninja-builder:"$key"
  docker rmi ghcr.io/gngpp/ninja-builder:"${map[$key]}"
done
