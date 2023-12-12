import os from 'os'
import path from 'path'
import { exit } from 'process'
import * as io from '@actions/io'
import { getMicromambaUrl, determineEnvironmentName } from './util'
import { PATHS, options } from './options'
import { shellInit } from './shell-init'
import { restoreCacheDownloads } from './cache'
import { core } from './core'
import {
  downloadMicromamba,
  generateCondarc,
  installEnvironment,
  generateMicromambaRunShell,
  generateInfo
} from './operations'

export * from './operations'

const addEnvironmentPathToOutput = () => {
  return determineEnvironmentName(options.environmentName, options.environmentFile).then((environmentName) => {
    const environmentPath = path.join(options.micromambaRootPath, 'envs', environmentName)
    core.debug(`Setting environment-path output to ${environmentPath}`)
    core.setOutput('environment-path', environmentPath)
  })
}

const setEnvVariables = () => {
  core.info('Set environment variables.')
  core.debug(`MAMBA_ROOT_PREFIX: ${options.micromambaRootPath}`)
  core.exportVariable('MAMBA_ROOT_PREFIX', options.micromambaRootPath)
  core.debug(`MAMBA_EXE: ${options.micromambaBinPath}`)
  core.exportVariable('MAMBA_EXE', options.micromambaBinPath)
  core.debug(`CONDARC: ${options.condarcFile}`)
  core.exportVariable('CONDARC', options.condarcFile)
}

const run = async () => {
  core.debug(`process.env.HOME: ${process.env.HOME}`)
  core.debug(`os.homedir(): ${os.homedir()}`)
  core.debug(`bashProfile ${PATHS.bashProfile}`)

  if (process.platform === 'win32') {
    // Work around bug in Mamba: https://github.com/mamba-org/mamba/issues/1779
    // This prevents using setup-micromamba without bash
    core.addPath(path.dirname(await io.which('cygpath', true)))
  }

  await downloadMicromamba(getMicromambaUrl(options.micromambaSource))
  await generateCondarc()
  await Promise.all(options.initShell.map((shell) => shellInit(shell)))
  const cacheDownloadsKey = await restoreCacheDownloads()
  core.saveState('cacheDownloadsCacheHit', cacheDownloadsKey !== undefined)
  if (options.createEnvironment) {
    await installEnvironment()
    await generateMicromambaRunShell()
    await addEnvironmentPathToOutput()
  }
  setEnvVariables()
  await generateInfo()
}

if (process.env.MOCKING || process.env.GITHUB_ACTIONS) {
  run().catch((error) => {
    if (core.isDebug()) {
      throw error
    }
    if (error instanceof Error) {
      core.setFailed(error.message)
      exit(1)
    } else if (typeof error === 'string') {
      core.setFailed(error)
      exit(1)
    }
    throw error
  })
}
