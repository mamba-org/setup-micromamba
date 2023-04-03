#!/usr/bin/env bash

DEBUG=0

export MOCKING=1

if [ $DEBUG -eq 1 ]; then
  node --inspect-brk --enable-source-maps dist/index.js
else
  node dist/index.js
fi
