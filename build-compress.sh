#!/usr/bin/env sh

set -e
set -o pipefail

MY_DIR=$(cd $(dirname $(readlink -f $0));pwd)
cd $MY_DIR

do_compress () {
  find "$1" \( -type f -name "*.wasm" -o -name "*.css" -o -name "*.js" -o -name "*.mjs" \) -exec zopfli {} \;
  find "$1" \( -type f -name "*.wasm" -o -name "*.css" -o -name "*.js" -o -name "*.mjs" \) -exec brotli -v -f -9 -o {}.br {} \;
  #find "$1" \( -type f -name "*.wasm" -o -name "*.css" -o -name "*.js" -o -name "*.mjs" \) -exec zstd -v -f -19 -o {}.zst {} \;
}

do_compress embed/challenge/
do_compress embed/assets/
