#!/bin/bash

set -e

root=$(pwd)
: ${tag=latest}
: ${rmi=false}
: ${os=linux}
[ ! -d uploads ] && mkdir uploads

cargo update
cargo install cargo-deb

pull_docker_image() {
    docker pull ghcr.io/gngpp/ninja-builder:$1
}

rmi_docker_image() {
    docker rmi ghcr.io/gngpp/ninja-builder:$1
}

build_macos_target() {
    cargo build --release --target $1
    sudo chmod -R 777 target
    cd target/$1/release
    upx --best --lzma ninja
    tar czvf ninja-$tag-$1.tar.gz ninja
    shasum -a 256 ninja-$tag-$1.tar.gz >ninja-$tag-$1.tar.gz.sha256
    mv ninja-$tag-$1.tar.gz $root/uploads/
    mv ninja-$tag-$1.tar.gz.sha256 $root/uploads/
    cd -
}

build_linux_target() {
    docker run --rm -t --user=$UID:$(id -g $USER) \
        -v $(pwd):/home/rust/src \
        -v $HOME/.cargo/registry:/root/.cargo/registry \
        -v $HOME/.cargo/git:/root/.cargo/git \
        ghcr.io/gngpp/ninja-builder:$1 cargo build --release
    sudo chmod -R 777 target
    upx --best --lzma target/$1/release/ninja
    cargo deb --target=$1 --no-build --no-strip
    cd target/$1/debian
    rename 's/.*/ninja-'$tag'-'$1'.deb/' *.deb
    mv ./* $root/uploads/
    cd -
    cd target/$1/release
    tar czvf ninja-$tag-$1.tar.gz ninja
    shasum -a 256 ninja-$tag-$1.tar.gz >ninja-$tag-$1.tar.gz.sha256
    mv ninja-$tag-$1.tar.gz $root/uploads/
    mv ninja-$tag-$1.tar.gz.sha256 $root/uploads/
    cd -
}

build_windows_target() {
    docker run --rm -t \
        -v $(pwd):/home/rust/src \
        -v $HOME/.cargo/registry:/usr/local/cargo/registry \
        -v $HOME/.cargo/git:/usr/local/cargo/git \
        ghcr.io/gngpp/ninja-builder:$1 cargo xwin build --release --target $1
    sudo chmod -R 777 target
    sudo upx --best --lzma target/$1/release/ninja.exe
    cd target/$1/release
    tar czvf ninja-$tag-$1.tar.gz ninja.exe
    shasum -a 256 ninja-$tag-$1.tar.gz >ninja-$tag-$1.tar.gz.sha256
    mv ninja-$tag-$1.tar.gz $root/uploads/
    mv ninja-$tag-$1.tar.gz.sha256 $root/uploads/
    cd -
}

if [ "$os" = "linux" ]; then
    target_list=(x86_64-unknown-linux-musl aarch64-unknown-linux-musl armv7-unknown-linux-musleabi armv7-unknown-linux-musleabihf armv5te-unknown-linux-musleabi arm-unknown-linux-musleabi arm-unknown-linux-musleabihf x86_64-pc-windows-msvc)

    for target in "${target_list[@]}"; do
        pull_docker_image "$target"

        if [ "$target" = "x86_64-pc-windows-msvc" ]; then
            build_windows_target "$target"
        else
            build_linux_target "$target"
        fi

        if [ "$rmi" = "true" ]; then
            rmi_docker_image "$target"
        fi
    done
fi

if [ "$os" = "macos" ]; then
    brew install upx
    rustup target add x86_64-apple-darwin aarch64-apple-darwin
    target_list=(x86_64-apple-darwin aarch64-apple-darwin)
    for target in "${target_list[@]}"; do
        build_macos_target "$target"
    done
fi

generate_directory_tree() {
    find "$1" -print | sed -e 's;[^/]*/;|____;g;s;____|; |;g'
}

generate_directory_tree "uploads"
