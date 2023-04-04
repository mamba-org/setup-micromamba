import * as fs from 'fs/promises'

import * as coreDefault from '@actions/core'
import fetch from 'node-fetch'
import { PATHS, sha256, getMicromambaUrlFromInputs } from './util'
import { coreMocked } from './mocking'
import { parseInputs } from './inputs'
import { shellInit } from './shell-init'

const core = process.env.MOCKING ? coreMocked : coreDefault

const downloadMicromamba = (url: string) => {
  core.startGroup('Install micromamba')
  core.debug(`Downloading micromamba from ${url} ...`)

  const mkDir = fs.mkdir(PATHS.micromambaBinFolder, { recursive: true })
  const downloadMicromamba = fetch(url)
    .then((res) => {
      if (!res.ok) {
        throw new Error(`Download failed: ${res.statusText}`)
      }
      return res.arrayBuffer()
    })
    .then((arrayBuffer) => Buffer.from(arrayBuffer))

  return Promise.all([mkDir, downloadMicromamba])
    .then(([, buffer]) => {
      core.debug(`micromamba binary sha256: ${sha256(buffer)}`)
      return fs.writeFile(PATHS.micromambaBin, buffer, { encoding: 'binary', mode: 0o755 })
    })
    .catch((err) => {
      core.error(`Error installing micromamba: ${err.message}`)
    })
    .finally(core.endGroup)
}

const run = async () => {
  const inputs = parseInputs()
  core.debug(`Parsed inputs: ${JSON.stringify(inputs, null, 2)}`)

  const url = getMicromambaUrlFromInputs(inputs.micromambaUrl, inputs.micromambaVersion)
  await downloadMicromamba(url)
  for (const shell of inputs.initMicromamba) {
    await shellInit(shell, inputs.logLevel)
  }
}

run()
