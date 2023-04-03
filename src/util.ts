import * as path from 'path'
import * as os from 'os'
import type { BinaryLike } from 'crypto'
import { createHash } from 'crypto'

export const PATHS = {
  // TODO fix paths
  // micromambaBinFolder: path.join(os.homedir(), 'micromamba-bin'),
  micromambaBinFolder: path.join(os.homedir(), 'debug', 'micromamba-bin'),
  // micromambaBin: path.join(os.homedir(), 'micromamba-bin', 'micromamba')
  micromambaBin: path.join(os.homedir(), 'debug', 'micromamba-bin', 'micromamba')
}

const getMicromambaUrl = (arch: string, version: string) => {
  return `https://github.com/mamba-org/micromamba-releases/releases/${version}/download/micromamba-${arch}`
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

export const getMicromambaUrlFromInputs = (micromambaUrl: string, micromambaVersion: string) => {
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
