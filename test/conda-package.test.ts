import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import {
  getCondaPackageExtractArgs,
  getCondaPackageExtension,
  toGnuTarPath
} from '../src/conda-package'

describe('getCondaPackageExtension', () => {
  it('detects .tar.bz2 and .conda package URLs', () => {
    assert.equal(
      getCondaPackageExtension('https://example.com/micromamba-2.9.0.rc1-0.tar.bz2'),
      '.tar.bz2'
    )
    assert.equal(getCondaPackageExtension('https://example.com/micromamba-2.9.0.rc1-0.conda'), '.conda')
  })
})

describe('toGnuTarPath', () => {
  it('converts Windows backslashes to forward slashes', () => {
    assert.equal(
      toGnuTarPath(String.raw`C:\Users\runneradmin\micromamba-bin\micromamba-extract`, 'win32'),
      'C:/Users/runneradmin/micromamba-bin/micromamba-extract'
    )
  })

  it('leaves Unix paths unchanged', () => {
    assert.equal(toGnuTarPath('/home/runner/micromamba-bin/pkg.tar.bz2', 'linux'), '/home/runner/micromamba-bin/pkg.tar.bz2')
    assert.equal(toGnuTarPath('/Users/runner/micromamba-bin/pkg.tar.bz2', 'darwin'), '/Users/runner/micromamba-bin/pkg.tar.bz2')
  })
})

describe('getCondaPackageExtractArgs', () => {
  const winPackagePath = String.raw`C:\Users\runneradmin\micromamba-bin\micromamba-package.tar.bz2`
  const winExtractDir = String.raw`C:\Users\runneradmin\micromamba-bin\micromamba-extract`
  const binaryMember = 'Library/bin/micromamba.exe'

  it('uses --force-local and forward-slash paths on Windows', () => {
    assert.deepEqual(getCondaPackageExtractArgs(winPackagePath, winExtractDir, binaryMember, 'win32'), [
      '--force-local',
      '-xjf',
      'C:/Users/runneradmin/micromamba-bin/micromamba-package.tar.bz2',
      '-C',
      'C:/Users/runneradmin/micromamba-bin/micromamba-extract',
      binaryMember
    ])
  })

  it('keeps relative paths as-is on Windows (preferred cwd-based extract)', () => {
    assert.deepEqual(
      getCondaPackageExtractArgs('micromamba-package.tar.bz2', 'micromamba-extract', binaryMember, 'win32'),
      ['--force-local', '-xjf', 'micromamba-package.tar.bz2', '-C', 'micromamba-extract', binaryMember]
    )
  })

  it('omits --force-local on Unix platforms (macOS bsdtar does not support it)', () => {
    const packagePath = '/home/runner/micromamba-bin/micromamba-package.tar.bz2'
    const extractDir = '/home/runner/micromamba-bin/micromamba-extract'
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
