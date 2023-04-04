import * as fs from 'fs/promises'
import * as coreDefault from '@actions/core'
import fetch from 'node-fetch'
import { PATHS, sha256, getMicromambaUrlFromInputs } from './util'
import { coreMocked } from './mocking'
import { Input, parseInputs, validateInputs } from './inputs'
import { shellInit } from './shell-init'
// import type { Input } from './inputs'

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

const generateCondarc = (inputs: Input) => {
  if (inputs.condarcFile) {
    core.debug(`Using condarc file ${inputs.condarcFile} ...`)
    return fs.access(inputs.condarcFile, fs.constants.F_OK)
  }
  if (inputs.condarc) {
    core.info(`Writing condarc contents to ${PATHS.condarc} ...`)
    return fs.writeFile(PATHS.condarc, inputs.condarc)
  }
  core.info('Adding conda-forge to condarc channels ...')
  return fs.writeFile(PATHS.condarc, 'channels:\n  - conda-forge')
}

// const createEnvironment = (inputs: Input) => {
//   core.startGroup('Create environment')
//   return Promise.resolve().finally(core.endGroup)
// }

const run = async () => {
  const inputs = parseInputs()
  core.debug(`Parsed inputs: ${JSON.stringify(inputs, null, 2)}`)
  validateInputs(inputs)

  const url = getMicromambaUrlFromInputs(inputs.micromambaUrl, inputs.micromambaVersion)
  await downloadMicromamba(url)
  await generateCondarc(inputs)
  await Promise.all(inputs.initShell.map((shell) => shellInit(shell, inputs)))
  // if (inputs.createEnvironment) {
  //   await createEnvironment(inputs)
  // }
}

run()
