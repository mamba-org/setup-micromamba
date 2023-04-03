import * as fs from 'fs/promises'
import * as coreDefault from '@actions/core'
import decompress from 'decompress'
import fetch from 'node-fetch'
import { PATHS, sha256, micromambaUrl, getCondaArch } from './util'
import { coreMocked } from './mocking'

const core = process.env.MOCKING ? coreMocked : coreDefault

const downloadMicromamba = (url: string) => {
  core.startGroup('Install micromamba')
  core.debug(`Downloading micromamba from ${url} ...`)

  const mkDir = fs.mkdir(PATHS.micromambaBinFolder, { recursive: true })
  const downloadMicromamba = fetch(url)
    .then((response) => response.arrayBuffer())
    .then((buffer) => Buffer.from(buffer))
    .then((buffer) => {
      core.debug(`.tar.bz2 sha256: ${sha256(buffer)}`)
      return decompress(buffer, {
        filter: (file) => file.path === 'bin/micromamba',
        map: (file) => {
          file.path = 'micromamba'
          return file
        }
      })
    })

  return Promise.all([mkDir, downloadMicromamba])
    .then(([, files]) => {
      const buffer = files[0].data
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
