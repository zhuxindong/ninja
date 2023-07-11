#!/bin/bash

set -e

root=$(pwd)
: ${tag=latest}
[ ! -d uploads ] && mkdir uploads

cargo update
cargo install cargo-deb

target_list=(x86_64-unknown-linux-musl aarch64-unknown-linux-musl armv7-unknown-linux-musleabi armv7-unknown-linux-musleabihf armv5te-unknown-linux-musleabi arm-unknown-linux-musleabi arm-unknown-linux-musleabihf x86_64-pc-windows-msvc)
for target in ${target_list[@]}; do
    docker pull ghcr.io/gngpp/opengpt-builder:$target

    if [ "$target" = "x86_64-pc-windows-msvc" ]; then
        docker run --rm -t \
            -v $(pwd):/home/rust/src \
            -v $HOME/.cargo/registry:/usr/local/cargo/registry \
            -v $HOME/.cargo/git:/usr/local/cargo/git \
            ghcr.io/gngpp/opengpt-builder:$target cargo xwin build --release --target x86_64-pc-windows-msvc
        sudo chmod -R 777 target
        sudo upx --lzma target/$target/release/opengpt.exe
    else
        docker run --rm -t \
            -v $(pwd):/home/rust/src \
            -v $HOME/.cargo/registry:/root/.cargo/registry \
            -v $HOME/.cargo/git:/root/.cargo/git \
            ghcr.io/gngpp/opengpt-builder:$target cargo build --release
        sudo chmod -R 777 target
        sudo upx --lzma target/$target/release/opengpt
    fi

    cargo deb --target=$target --no-build --no-strip
    cd target/$target/debian
    rename 's/.*/opengpt-'$tag'-'$target'.deb/' *.deb
    mv ./* $root/uploads/
    cd -

    cd target/$target/release
    tar czvf opengpt-$tag-$target.tar.gz opengpt
    shasum -a 256 opengpt-$tag-$target.tar.gz >opengpt-$tag-$target.tar.gz.sha256
    mv opengpt-$tag-$target.tar.gz $root/uploads/
    mv opengpt-$tag-$target.tar.gz.sha256 $root/uploads/
    cd -

done

tree -h uploads
