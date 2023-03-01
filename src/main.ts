import * as https from 'https'
import * as fs from 'fs/promises'
import * as crypto from 'crypto'
import * as core from '@actions/core'
import { wait } from './wait'
import { PATHS, sha256, micromambaUrl } from './util'

async function downloadMicromamba(url: string) {
  await fs.mkdir(PATHS.micromambaBinFolder, { recursive: true })
  const tarBz2Path = PATHS.micromambaBin + '.tar.bz2'
  core.debug(`Downloading micromamba from ${url} to ${tarBz2Path} ...`)
  fetch(url)
    .then((response) => {
      return response.arrayBuffer()
    })
    .then((buffer) => Buffer.from(buffer))
    .then((buffer) => {
      fs.writeFile(tarBz2Path, buffer, 'binary')
      core.debug(`Downloaded micromamba to ${tarBz2Path} ...`)
      core.debug(`SHA256: ${sha256(buffer)}`)
    })
    .catch((err) => {
      core.error(`Error downloading file: ${err.message}`)
    })
}

const run = async () => {
  // try {
  //   const ms: string = core.getInput('milliseconds')
  //   core.debug(`Waiting ${ms} milliseconds ...`) // debug is only output if you set the secret `ACTIONS_STEP_DEBUG` to true
  //   core.debug(new Date().toTimeString())
  //   await wait(parseInt(ms, 10))
  //   core.debug(new Date().toTimeString())
  //   core.setOutput('time', new Date().toTimeString())
  // } catch (error) {
  //   if (error instanceof Error) core.setFailed(error.message)
  // }
  await downloadMicromamba(micromambaUrl('osx-arm64', '1.3.0'))
}

run()
