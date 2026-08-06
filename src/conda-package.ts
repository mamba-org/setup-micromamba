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
 * Normalize a filesystem path for GNU tar on the given platform.
 *
 * Git-for-Windows GNU tar mis-parses backslash paths (e.g. `-C C:\Users\...`
 * becomes `C\:\\Users\...` and fails with "Cannot open: No such file or directory").
 * Forward slashes work; pair with `--force-local` so drive-letter colons are not
 * treated as remote-host separators. macOS bsdtar does not support `--force-local`.
 */
export const toGnuTarPath = (filePath: string, platform: NodeJS.Platform = os.platform()): string => {
  if (platform !== 'win32') {
    return filePath
  }
  return filePath.replace(/\\/g, '/')
}

/**
 * Build tar args to extract a member from a local conda .tar.bz2 package.
 *
 * Prefer calling this with paths relative to `cwd` (see
 * `extractMicromambaFromCondaPackage`) so Windows drive letters never reach tar.
 * Absolute Windows paths are still normalized to forward slashes + `--force-local`.
 */
export const getCondaPackageExtractArgs = (
  packagePath: string,
  extractDir: string,
  binaryMember: string,
  platform: NodeJS.Platform = os.platform()
): string[] => {
  const args = [
    '-xjf',
    toGnuTarPath(packagePath, platform),
    '-C',
    toGnuTarPath(extractDir, platform),
    binaryMember
  ]
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
  const packageDir = path.dirname(packagePath)
  const extractDirName = 'micromamba-extract'
  const extractDir = path.join(packageDir, extractDirName)
  await fs.mkdir(extractDir, { recursive: true })

  if (packagePath.endsWith('.tar.bz2')) {
    // Use cwd + relative paths so GNU tar never sees Windows drive-letter paths.
    await execFileAsync(
      'tar',
      getCondaPackageExtractArgs(path.basename(packagePath), extractDirName, binaryMember),
      { cwd: packageDir }
    )
  } else if (packagePath.endsWith('.conda')) {
    throw new Error(
      'Prerelease micromamba packages in .conda format are not supported yet. Use a .tar.bz2 build or specify micromamba-url.'
    )
  } else {
    throw new Error(`Unsupported micromamba package format: ${packagePath}`)
  }

  await fs.copyFile(path.join(extractDir, binaryMember), destBinaryPath)
}
