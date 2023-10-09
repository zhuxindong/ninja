#!/bin/bash

set -e

root=$(pwd)
: ${tag=latest}
[ ! -d uploads ] && mkdir uploads


curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh -s -- -y
source "$HOME/.cargo/env"
sudo apt-get install gcc g++ cmake libclang-dev -y 
cargo build --release

sudo chmod -R 777 target
cd target/release
tar czvf ninja-$tag-linux_x86_64.tar.gz ninja
shasum -a 256 ninja-$tag-linux_x86_64.tar.gz >ninja-$tag-linux_x86_64.tar.gz.sha256
mv ninja-$tag-linux_x86_64.tar.gz $root/uploads/
mv ninja-$tag-linux_x86_64.tar.gz.sha256 $root/uploads/
