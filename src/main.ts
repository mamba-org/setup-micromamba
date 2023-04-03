import * as fs from 'fs/promises'
import * as coreDefault from '@actions/core'
import fetch from 'node-fetch'
import { PATHS, sha256, getMicromambaUrlFromInputs } from './util'
import { coreMocked } from './mocking'
import { micromambaUrlSchema, micromambaVersionSchema } from './schemas'

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
      fs.writeFile(PATHS.micromambaBin, buffer, { encoding: 'binary', mode: 0o755 })
      core.debug(`Downloaded micromamba executable to ${PATHS.micromambaBin} ...`)
    })
    .catch((err) => {
      core.error(`Error installing micromamba: ${err.message}`)
    })
}

const run = async () => {
  const inputs = {
    micromambaUrl: micromambaUrlSchema.parse(core.getInput('micromamba-url')),
    micromambaVersion: micromambaVersionSchema.parse(core.getInput('micromamba-version'))
    // logLevel: logLevelSchema.parse(core.getInput('log-level')),
    // condarcFile: core.getInput('condarc-file'),
    // environmentFile: core.getInput('environment-file'),
    // environmentName: core.getInput('environment-name'),
    // extraSpecs: extraSpecsSchema.parse(JSON.parse(core.getInput('extra-specs'))),
    // createArgs: createArgsSchema.parse(JSON.parse(core.getInput('create-args'))),
    // createEnv: createEnvSchema.parse(JSON.parse(core.getInput('create-env'))),
    // cacheKey: core.getInput('cache-key'),
    // initMicromamba: initMicromambaSchema.parse(JSON.parse(core.getInput('init-micromamba')))
  }

  core.info(`Inputs: ${JSON.stringify(inputs, null, 2)}`)

  // const inputs = {
  //   micromambaVersion: core.getInput('micromamba-version'),
  //   micromambaUrl: core.getInput('micromamba-url')

  // }
  // await installMicromamba()
  const url = getMicromambaUrlFromInputs(inputs.micromambaUrl, inputs.micromambaVersion)
  await downloadMicromamba(url)
}

run()
