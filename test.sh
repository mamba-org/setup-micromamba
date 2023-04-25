#!/usr/bin/env bash

DEBUG=0

export MOCKING=1
export INPUT_MICROMAMBA_URL=""
export INPUT_MICROMAMBA_VERSION=""
export INPUT_LOG_LEVEL=""
export INPUT_CONDARC_FILE=""
export INPUT_CONDARC=""
export INPUT_ENVIRONMENT_FILE=""
export INPUT_ENVIRONMENT_NAME=""
export INPUT_CREATE_ARGS=""
export INPUT_CREATE_ENVIRONMENT="false"
export INPUT_INIT_SHELL=""
export INPUT_GENERATE_RUN_SHELL=""
export INPUT_POST_CLEANUP=""
export INPUT_CACHE_DOWNLOADS=""
export INPUT_CACHE_DOWNLOADS_KEY=""
export INPUT_CACHE_ENVIRONMENT=""
export INPUT_CACHE_ENVIRONMENT_KEY=""
export INPUT_MICROMAMBA_ROOT_PATH="~/debug/micromamba"
export INPUT_MICROMAMBA_BINARY_PATH="~/debug/micromamba/micromamba"

if [ $DEBUG -eq 1 ]; then
  node --inspect-brk --enable-source-maps dist/index.js
  node --inspect-brk --enable-source-maps dist/post.js
else
  node --enable-source-maps dist/index.js
  node --enable-source-maps dist/post.js
fi
