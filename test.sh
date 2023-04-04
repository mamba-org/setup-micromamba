#!/usr/bin/env bash

DEBUG=0

export MOCKING=1
export INPUT_MICROMAMBA_URL=""
export INPUT_MICROMAMBA_VERSION=""
export INPUT_LOG_LEVEL="debug"
export INPUT_CONDARC_FILE="~/.condarc"
export INPUT_ENVIRONMENT_FILE=""
export INPUT_ENVIRONMENT_NAME=""
export INPUT_EXTRA_SPECS=""
export INPUT_CREATE_ARGS=""
export INPUT_CREATE_ENVIRONMENT="true"
export INPUT_CACHE_KEY=""
export INPUT_INIT_SHELL="[\"bash\"]"

if [ $DEBUG -eq 1 ]; then
  node --inspect-brk --enable-source-maps dist/index.js
else
  node --enable-source-maps dist/index.js
fi
