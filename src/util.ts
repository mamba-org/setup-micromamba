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

export const micromambaUrl = (os: string, version: string) => {
  return `https://micro.mamba.pm/api/micromamba/${os}/${version}`
}

export const sha256 = (s: BinaryLike) => {
  return createHash('sha256').update(s).digest('hex')
}
