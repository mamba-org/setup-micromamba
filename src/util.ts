import * as path from 'path'
import * as os from 'os'
import type { BinaryLike } from 'crypto'
import { createHash } from 'crypto'
import * as coreDefault from '@actions/core'
import { exec } from '@actions/exec'
import { coreMocked } from './mocking'
import type { LogLevelType } from './inputs'

const core = process.env.MOCKING ? coreMocked : coreDefault

export const PATHS = {
  // TODO fix paths
  micromambaBinFolder: path.join(os.homedir(), 'debug', 'micromamba-bin'),
  micromambaBin: path.join(os.homedir(), 'debug', 'micromamba-bin', 'micromamba'),
  micromambaRoot: path.join(os.homedir(), 'debug', 'micromamba-root'),
  micromambaEnvs: path.join(os.homedir(), 'debug', 'micromamba-root', 'envs')
}

const getMicromambaUrl = (arch: string, version: string) => {
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

export const getMicromambaUrlFromInputs = (
  micromambaUrl: string | undefined,
  micromambaVersion: string | undefined
) => {
  if (micromambaUrl) {
    return micromambaUrl
  }
  const arch = getCondaArch()
  if (!micromambaVersion) {
    return getMicromambaUrl(arch, 'latest')
  }
  return getMicromambaUrl(arch, micromambaVersion)
}

export const sha256 = (s: BinaryLike) => {
  return createHash('sha256').update(s).digest('hex')
}

export const micromambaCmd = (command: string, logLevel: LogLevelType) => {
  return [PATHS.micromambaBin, command, '--log-level', logLevel]
}

export const execute = (cmd: string[]) => {
  core.debug(`Executing: ${cmd.join(' ')}`)
  return exec(cmd[0], cmd.slice(1))
}
