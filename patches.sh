#!/bin/bash

if [ -d "patches" ]; then
    rm -rf patches
fi

if [ -n "$GIT_TOKEN" ]; then
    git clone https://x-access-token:$GIT_TOKEN@github.com/gngpp/ninja-patches patches

    if [ $(ls patches/*.patch 2> /dev/null | wc -l) -gt 0 ]; then
        for patch in patches/*.patch; do
            git apply "$patch"
        done
    fi
fi