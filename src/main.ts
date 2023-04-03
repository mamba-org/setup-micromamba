import * as fs from 'fs/promises'
import * as coreDefault from '@actions/core'
import fetch from 'node-fetch'
import * as z from 'zod'
import { PATHS, sha256, getMicromambaUrlFromInputs } from './util'
import { coreMocked } from './mocking'

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

const parseOrUndefined = <T>(input: string, schema: z.ZodSchema<T>): T | undefined => {
  if (input === '') {
    return undefined
  }
  return schema.parse(input)
}

const run = async () => {
  const inputs = {
    // TODO: parseOrUndefined is not needed everywhere
    micromambaUrl: parseOrUndefined(core.getInput('micromamba-url'), z.string().url()),
    micromambaVersion: parseOrUndefined(
      core.getInput('micromamba-version'),
      z.union([z.literal('latest'), z.string().regex(/^\d+\.\d+\.\d+-\d+$/)])
    ),
    logLevel: parseOrUndefined(core.getInput('log-level'), z.enum(['debug', 'info'])),
    condarcFile: parseOrUndefined(core.getInput('condarc-file'), z.string()),
    environmentFile: parseOrUndefined(core.getInput('environment-file'), z.string()),
    environmentName: parseOrUndefined(core.getInput('environment-name'), z.string()),
    extraSpecs: parseOrUndefined(core.getInput('extra-specs'), z.array(z.string())),
    createArgs: parseOrUndefined(core.getInput('create-args'), z.array(z.string())),
    createEnvironment: parseOrUndefined(JSON.parse(core.getInput('create-environment')), z.boolean()),
    cacheKey: parseOrUndefined(core.getInput('cache-key'), z.string()),
    initMicromamba: parseOrUndefined(
      core.getInput('init-micromamba') && JSON.parse(core.getInput('init-micromamba')),
      z.array(z.enum(['bash', 'zsh', 'xonsh', 'powershell', 'cmd']))
    )
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
