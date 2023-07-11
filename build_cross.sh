#!/bin/bash

set -e

root=$(pwd)
: ${tag=latest}
[ ! -d uploads ] && mkdir uploads

cargo update
cargo install cargo-deb

pull_docker_image() {
    docker pull ghcr.io/gngpp/opengpt-builder:$1
}

build_target() {
    docker run --rm -t \
        -v $(pwd):/home/rust/src \
        -v $HOME/.cargo/registry:/root/.cargo/registry \
        -v $HOME/.cargo/git:/root/.cargo/git \
        ghcr.io/gngpp/opengpt-builder:$1 cargo build --release
    sudo chmod -R 777 target
    sudo upx --lzma target/$1/release/opengpt
    cargo deb --target=$1 --no-build --no-strip
    cd target/$1/debian
    rename 's/.*/opengpt-'$tag'-'$1'.deb/' *.deb
    mv ./* $root/uploads/
    cd -
    cd target/$1/release
    tar czvf opengpt-$tag-$1.tar.gz opengpt
    shasum -a 256 opengpt-$tag-$1.tar.gz >opengpt-$tag-$1.tar.gz.sha256
    mv opengpt-$tag-$1.tar.gz $root/uploads/
    mv opengpt-$tag-$1.tar.gz.sha256 $root/uploads/
    cd -
}

build_windows_target() {
    docker run --rm -t \
        -v $(pwd):/home/rust/src \
        -v $HOME/.cargo/registry:/usr/local/cargo/registry \
        -v $HOME/.cargo/git:/usr/local/cargo/git \
        ghcr.io/gngpp/opengpt-builder:$1 cargo xwin build --release --target x86_64-pc-windows-msvc
    sudo chmod -R 777 target
    sudo upx --lzma target/$1/release/opengpt.exe
    cd target/$1/release
    tar czvf opengpt-$tag-$1.tar.gz opengpt.exe
    shasum -a 256 opengpt-$tag-$1.tar.gz >opengpt-$tag-$1.tar.gz.sha256
    mv opengpt-$tag-$1.tar.gz $root/uploads/
    mv opengpt-$tag-$1.tar.gz.sha256 $root/uploads/
    cd -
}

target_list=(x86_64-pc-windows-msvc)

for target in "${target_list[@]}"; do
    pull_docker_image "$target"

    if [ "$target" = "x86_64-pc-windows-msvc" ]; then
        build_windows_target "$target"
    else
        build_target "$target"
    fi
done

generate_directory_tree() {
    find "$1" -print | sed -e 's;[^/]*/;|____;g;s;____|; |;g'
}

generate_directory_tree "uploads"
