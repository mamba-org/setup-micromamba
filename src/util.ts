import * as path from 'path'
import * as os from 'os'
import { createHash } from 'crypto'

export const PATHS = {
  // TODO fix paths
  // micromambaBinFolder: path.join(os.homedir(), 'micromamba-bin'),
  micromambaBinFolder: path.join(os.homedir(), 'debug', 'micromamba-bin'),
  // micromambaBin: path.join(os.homedir(), 'micromamba-bin', 'micromamba')
  micromambaBin: path.join(os.homedir(), 'debug', 'micromamba-bin', 'micromamba')
}

export const micromambaUrl = (os: string, version: string) => {
  return `https://micro.mamba.pm/api/micromamba/${os}/${version}`
}

export const sha256 = (s: Buffer) => {
  const h = createHash('sha256')
  h.update(s)
  return h.digest().hexSlice()
}

export const sha256Short = (s: string) => {
  return sha256(s).substr(0, 8)
}
