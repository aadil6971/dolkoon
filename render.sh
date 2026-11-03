#!/bin/zsh
# QA: render Dolkoon views with fake data to PNGs in $1 (default ./qa).
set -e
cd "${0:A:h}"
OUT=${1:-qa}; mkdir -p $OUT
swiftc -O -target arm64-apple-macos14 Sources/Collector.swift Sources/Model.swift Sources/Theme.swift Sources/Views.swift Render/main.swift -o /tmp/dolkoon-render
/tmp/dolkoon-render $OUT
