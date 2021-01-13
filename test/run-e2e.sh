#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

export GOTESTSUM_FORMAT="${GOTESTSUM_FORMAT:-testname}"

gotestsum -- -v "$@" $SCRIPT_DIR/...
