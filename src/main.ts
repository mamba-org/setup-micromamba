import * as fs from 'fs/promises'
import * as coreDefault from '@actions/core'
import fetch from 'node-fetch'
import { PATHS, sha256, micromambaUrl, getCondaArch } from './util'
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

const run = async () => {
  // const inputs = {
  //   micromambaVersion: core.getInput('micromamba-version'),
  //   micromambaUrl: core.getInput('micromamba-url')

  // }
  // await installMicromamba()
  await downloadMicromamba(micromambaUrl(getCondaArch(), 'latest'))
}

run()
