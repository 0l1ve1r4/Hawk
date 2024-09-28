#!/bin/bash

ARG1="${1:-default}"
PATH_TO_EXEC="target/release/Hawk"

release() {
  cargo build --release
}

no_release() {
  cargo build
}

add_privileges() {
  sudo setcap cap_net_raw,cap_net_admin=eip "$PATH_TO_EXEC"
}

run() {
  "$PATH_TO_EXEC"
}

usage() {
  echo "Usage: $0 [release | no-release]"
  echo ""
  echo "--release: Build and run in release mode and run"
  echo "--no-release: Build and run in debug mode and run"
  exit 1
}

main() {
  if [ "$ARG1" == "--release" ]; then
    release
    PATH_TO_EXEC="target/release/Hawk"
    add_privileges
    run

  elif [ "$ARG1" == "--no-release" ]; then
    no_release
    PATH_TO_EXEC="target/debug/Hawk"
    add_privileges
    run

  else
    usage
  fi
}

main
