import * as fs from 'fs/promises'
import * as os from 'os'
import type { BinaryLike } from 'crypto'
import { createHash } from 'crypto'
import * as yaml from 'js-yaml'
import * as coreDefault from '@actions/core'
import { exec } from '@actions/exec'
import { match } from 'fp-ts/Either'
import { pipe } from 'fp-ts/function'
import * as z from 'zod'
import { coreMocked } from './mocking'
import type { LogLevelType, MicromambaSourceType, Options } from './options'

const core = process.env.MOCKING ? coreMocked : coreDefault

const getMicromambaUrlFromVersion = (arch: string, version: string) => {
  if (version === 'latest') {
    return `https://github.com/mamba-org/micromamba-releases/releases/latest/download/micromamba-${arch}`
  }
  return `https://github.com/mamba-org/micromamba-releases/releases/download/${version}/micromamba-${arch}`
}

export const getCondaArch = () => {
  const archDict: Record<string, string> = {
    'darwin-x64': 'osx-64',
    'darwin-arm64': 'osx-arm64',
    'linux-x64': 'linux-64',
    'linux-arm64': 'linux-aarch64',
    'linux-ppc64': 'linux-ppc64le',
    'win32-x64': 'win-64',
    'win32-arm64': 'win-arm64'
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
    throw new Error('No environment name or file specified.')
  }
  return fs
    .readFile(environmentFile)
    .then((fileContents) => {
      const environmentFileSchema = z.object({
        name: z.string()
      })
      const environmentName = environmentFileSchema.parse(yaml.load(fileContents.toString())).name
      core.debug(`Determined environment name from file ${environmentFile}: ${environmentName}`)
      return environmentName
    })
    .catch((error) => {
      core.error(`Could not determine environment name from file ${environmentFile}`)
      core.error(`Error: ${error}`)
      core.error(
        'If your environment file is not a YAML file containing `name` at the top level, please specify the environment name directly.'
      )
      throw error
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

export const sha256 = (s: BinaryLike) => createHash('sha256').update(s).digest('hex')

export const sha256Short = (s: BinaryLike) => sha256(s).slice(0, 7)

export const micromambaCmd = (options: Options, command: string, logLevel?: LogLevelType, condarcFile?: string) => {
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

// https://github.com/actions/toolkit/issues/518
export const getTempDirectory = () => {
  const tempDirectory = process.env.RUNNER_TEMP
  if (!tempDirectory) {
    throw new Error("Expected 'RUNNER_TEMP' to be defined")
  }
  return tempDirectory
}
