import * as fs from 'fs/promises'
import * as os from 'os'
import type { BinaryLike } from 'crypto'
import { createHash } from 'crypto'
import * as coreDefault from '@actions/core'
import { exec } from '@actions/exec'
import { match } from 'fp-ts/Either'
import { pipe } from 'fp-ts/function'
import { coreMocked } from './mocking'
import { options } from './options'
import type { LogLevelType, MicromambaSourceType } from './options'

const core = process.env.MOCKING ? coreMocked : coreDefault

const getMicromambaUrlFromVersion = (arch: string, version: string) => {
  if (version === 'latest') {
    return `https://github.com/mamba-org/micromamba-releases/releases/latest/download/micromamba-${arch}`
  }
  return `https://github.com/mamba-org/micromamba-releases/releases/download/${version}/micromamba-${arch}`
}

const getCondaArch = () => {
  const archDict: Record<string, string> = {
    'darwin-x64': 'osx-64',
    'darwin-arm64': 'osx-arm64',
    'linux-x64': 'linux-64',
    'linux-arm64': 'linux-aarch64',
    'linux-ppc64': 'linux-ppc64le',
    'win32-x64': 'win-64'
  }
  const arch = archDict[`${os.platform()}-${os.arch()}`]
  if (!arch) {
    throw new Error(`Unsupported platform: ${os.platform()}-${os.arch()}`)
  }
  return arch
}

export const determineEnvironmentName = (environmentName?: string, environmentFile?: string) => {
  core.debug('Determining environment name from inputs.')
  core.debug(`environmentName: ${environmentName}`)
  core.debug(`environmentFile: ${environmentFile}`)
  if (environmentName) {
    core.debug(`Determined environment name: ${environmentName}`)
    return Promise.resolve(environmentName)
  }
  if (!environmentFile) {
    // This should never happen, because validateInputs should have thrown an error
    // TODO: make this prettier
    core.error('No environment name or file specified.')
    throw new Error()
  }
  return fs.readFile(environmentFile, 'utf8').then((fileContents) => {
    const environmentName = fileContents.toString().match(/name:\s*(.*)/)?.[1]
    if (!environmentName) {
      const errorMessage = `Could not determine environment name from file ${environmentFile}`
      core.error(errorMessage)
      throw new Error(errorMessage)
    }
    core.debug(`Determined environment name from file ${environmentFile}: ${environmentName}`)
    return environmentName
  })
}

export const mambaRegexBlock =
  /\n# >>> mamba initialize >>>(?:\n|\r\n)?([\s\S]*?)# <<< mamba initialize <<<(?:\n|\r\n)?/

export const getMicromambaUrl = (micromambaSource: MicromambaSourceType) => {
  return pipe(
    micromambaSource,
    match(
      (version) => getMicromambaUrlFromVersion(getCondaArch(), version),
      (url) => url
    )
  )
}

export const sha256 = (s: BinaryLike) => {
  return createHash('sha256').update(s).digest('hex')
}

export const micromambaCmd = (command: string, logLevel?: LogLevelType, condarcFile?: string) => {
  let commandArray = [options.micromambaBinPath].concat(command.split(' '))
  if (logLevel) {
    commandArray = commandArray.concat(['--log-level', logLevel])
  }
  if (condarcFile) {
    commandArray = commandArray.concat(['--rc-file', condarcFile])
  }
  return commandArray
}

export const execute = (cmd: string[]) => {
  core.debug(`Executing: ${cmd.join(' ')}`)
  return exec(cmd[0], cmd.slice(1))
}
