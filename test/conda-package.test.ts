import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { getCondaPackageExtractArgs, getCondaPackageExtension } from '../src/conda-package'

describe('getCondaPackageExtension', () => {
  it('detects .tar.bz2 and .conda package URLs', () => {
    assert.equal(
      getCondaPackageExtension('https://example.com/micromamba-2.9.0.rc1-0.tar.bz2'),
      '.tar.bz2'
    )
    assert.equal(getCondaPackageExtension('https://example.com/micromamba-2.9.0.rc1-0.conda'), '.conda')
  })
})

describe('getCondaPackageExtractArgs', () => {
  const packagePath = String.raw`C:\Users\runneradmin\micromamba-bin\micromamba-package.tar.bz2`
  const extractDir = String.raw`C:\Users\runneradmin\micromamba-bin\micromamba-extract`
  const binaryMember = 'Library/bin/micromamba.exe'

  it('passes --force-local on Windows so drive-letter paths are not treated as remote hosts', () => {
    assert.deepEqual(getCondaPackageExtractArgs(packagePath, extractDir, binaryMember, 'win32'), [
      '--force-local',
      '-xjf',
      packagePath,
      '-C',
      extractDir,
      binaryMember
    ])
  })

  it('omits --force-local on Unix platforms (macOS bsdtar does not support it)', () => {
    for (const platform of ['linux', 'darwin'] as const) {
      assert.deepEqual(getCondaPackageExtractArgs(packagePath, extractDir, binaryMember, platform), [
        '-xjf',
        packagePath,
        '-C',
        extractDir,
        binaryMember
      ])
    }
  })
})
