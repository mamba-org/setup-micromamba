#!/usr/bin/env bash

DEBUG=1

export MOCKING=1
export INPUT_MICROMAMBA_URL=""
export INPUT_MICROMAMBA_VERSION=""
export INPUT_LOG_LEVEL="debug"
export INPUT_CONDARC_FILE="~/.condarc"
export INPUT_ENVIRONMENT_FILE="environment.yml"
export INPUT_ENVIRONMENT_NAME=""
export INPUT_EXTRA_SPECS=""
export INPUT_CREATE_ARGS=""
export INPUT_CREATE_ENVIRONMENT="true"
export INPUT_CACHE_KEY=""
export INPUT_INIT_MICROMAMBA="[]"

if [ $DEBUG -eq 1 ]; then
  node --enable-source-maps dist/index.js
  # node --inspect-brk --enable-source-maps dist/index.js
else
  node dist/index.js
fi
