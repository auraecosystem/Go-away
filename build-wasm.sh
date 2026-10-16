#!/usr/bin/env bash
VERSION="0.42.0"

set -e
set -o pipefail

cd "$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

mkdir -p .bin/ 2>/dev/null

# Setup tinygo first
if [[ ! -d .bin/tinygo ]]; then
  pushd .bin
  case "$(uname -s)" in
  Linux)
    os=linux
    ext=tar.gz
    ;;
  Darwin)
    os=darwin
    ext=tar.gz
    ;;
  MINGW* | MSYS* | CYGWIN*)
    os=windows
    ext=zip
    ;;
  *)
    echo "Unsupported OS: $(uname -s)" >&2
    exit 1
    ;;
  esac
  case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  armv6l | armv7l | armv8l) arch=armhf ;;
  *)
    echo "Unsupported arch: $(uname -m)" >&2
    exit 1
    ;;
  esac
  url="https://github.com/tinygo-org/tinygo/releases/download/v${VERSION}/tinygo${VERSION}.${os}-${arch}.${ext}"
  archive="tinygo${VERSION}.${os}-${arch}.${ext}"
  wget -c "${url}"
  if [[ "$ext" == "zip" ]]; then
    command -v unzip >/dev/null || {
      echo "unzip is required" >&2
      exit 1
    }
  fi
  if [[ "$ext" == "zip" ]]; then
    unzip -q "$archive"
  else
    tar -xzf "$archive"
  fi
  popd
fi

pushd .bin/tinygo

export TINYGOROOT="$(realpath .)"
export PATH="$(realpath ./bin/):$PATH"

popd

go generate ./...
