#!/bin/bash

set -e

root=$(pwd)
: ${tag=latest}
[ ! -d uploads ] && mkdir uploads


echo 1 | curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh
sudu apt-get install -y gcc g++ cmake libclang-dev 
cargo build --release


cd target/release
tar czvf ninja-$tag-linux_x86.tar.gz ninja
shasum -a 256 ninja-$tag-linux_x86.tar.gz >ninja-$tag-linux_x86.tar.gz.sha256
mv ninja-$tag-linux_x86.tar.gz $root/uploads/
mv ninja-$tag-linux_x86.tar.gz.sha256 $root/uploads/
