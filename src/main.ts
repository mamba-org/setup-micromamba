import * as fs from 'fs/promises'
import * as core from '@actions/core'
import decompress from 'decompress'
import { PATHS, sha256, micromambaUrl } from './util'

async function downloadMicromamba(url: string) {
  await fs.mkdir(PATHS.micromambaBinFolder, { recursive: true })
  core.debug(`Downloading micromamba from ${url} ...`)
  fetch(url)
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
    .then((files) => {
      const buffer = files[0].data
      fs.writeFile(PATHS.micromambaBin, buffer, { encoding: 'binary', mode: 0o755 })
      core.debug(`Downloaded micromamba executable to ${PATHS.micromambaBin} ...`)
    })
    .catch((err) => {
      core.error(`Error downloading file: ${err.message}`)
    })
}

const run = async () => {
  await downloadMicromamba(micromambaUrl('osx-arm64', '1.3.0'))
}

run()
