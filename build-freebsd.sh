#!/usr/bin/env sh

pkg install -y zopfli brotli go

MY_DIR=$(cd $(dirname $(readlink -f $0));pwd)
cd $MY_DIR

. build-compress.sh

cd cmd/go-away/
go build -o /usr/local/sbin/go-away
