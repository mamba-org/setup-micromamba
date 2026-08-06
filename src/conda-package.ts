import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { execFile as execFileChild } from 'child_process'
import { promisify } from 'util'

const execFileAsync = promisify(execFileChild)

export const getCondaPackageExtension = (packageUrl: string): string => {
  const pathname = new URL(packageUrl).pathname
  if (pathname.endsWith('.tar.bz2')) {
    return '.tar.bz2'
  }
  if (pathname.endsWith('.conda')) {
    return '.conda'
  }
  return '.tar.bz2'
}

/**
 * Build tar args to extract a member from a local conda .tar.bz2 package.
 *
 * On Windows, GNU tar treats ":" as a remote-host separator (`host:path`). Paths
 * like `C:\...` then fail with "Cannot connect to C: resolve failed". `--force-local`
 * disables that; only pass it on win32 because macOS bsdtar does not support it.
 */
export const getCondaPackageExtractArgs = (
  packagePath: string,
  extractDir: string,
  binaryMember: string,
  platform: NodeJS.Platform = os.platform()
): string[] => {
  const args = ['-xjf', packagePath, '-C', extractDir, binaryMember]
  if (platform === 'win32') {
    args.unshift('--force-local')
  }
  return args
}

export const extractMicromambaFromCondaPackage = async (
  packagePath: string,
  destBinaryPath: string,
  binaryMember: string
) => {
  const extractDir = path.join(path.dirname(packagePath), 'micromamba-extract')
  await fs.mkdir(extractDir, { recursive: true })

  if (packagePath.endsWith('.tar.bz2')) {
    await execFileAsync('tar', getCondaPackageExtractArgs(packagePath, extractDir, binaryMember))
  } else if (packagePath.endsWith('.conda')) {
    throw new Error(
      'Prerelease micromamba packages in .conda format are not supported yet. Use a .tar.bz2 build or specify micromamba-url.'
    )
  } else {
    throw new Error(`Unsupported micromamba package format: ${packagePath}`)
  }

  await fs.copyFile(path.join(extractDir, binaryMember), destBinaryPath)
}
