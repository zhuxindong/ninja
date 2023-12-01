#!/bin/bash

if [ -d "patches" ]; then
    rm -rf patches
fi

if [ -n "$GIT_TOKEN" ]; then
    git clone https://gngpp:$GIT_TOKEN@github.com/gngpp/ninja-patches patches
    
    for patch in patches/*.patch; do
        git apply "$patch"
    done
fi