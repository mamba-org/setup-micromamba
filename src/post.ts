import * as fs from 'fs/promises'
import * as os from 'os'
import path from 'path'
import { exit } from 'process'
import * as coreDefault from '@actions/core'
import { coreMocked } from './mocking'
import { getOptions, type Options } from './options'
import { determineEnvironmentName } from './util'
import { removeEnvironmentFromAutoActivate, shellDeinit } from './shell-init'
import { saveCacheDownloads } from './cache'

const core = process.env.MOCKING ? coreMocked : coreDefault

const removeMicromambaRunShell = (options: Options) => {
  if (!options.generateRunShell || os.platform() === 'win32') {
    return Promise.resolve(undefined)
  }
  core.info('Removing micromamba run shell ...')
  return fs.rm(options.micromambaRunShellPath)
}

const uninstallEnvironment = (options: Options) => {
  return determineEnvironmentName(options.environmentName, options.environmentFile).then((environmentName) => {
    const envPath = path.join(options.micromambaRootPath, 'envs', environmentName)
    core.info(`Removing environment ${environmentName} ...`)
    core.debug(`Deleting ${envPath}`)
    return fs.rm(envPath, { recursive: true })
  })
}

const removeRoot = (options: Options) => {
  core.info('Removing micromamba root ...')
  core.debug(`Deleting ${options.micromambaRootPath}`)
  return fs.rm(options.micromambaRootPath, { recursive: true })
}

const removeCustomCondarc = (options: Options) => {
  if (!options.writeToCondarc) {
    return Promise.resolve(undefined)
  }
  core.info('Removing custom condarc ...')
  core.debug(`Deleting ${options.condarcFile}`)
  return fs.rm(options.condarcFile)
}

const removeMicromambaBinaryParentIfEmpty = (options: Options) => {
  const parentDir = path.dirname(options.micromambaBinPath)
  return fs.readdir(parentDir).then((files) => {
    // if the folder is empty, remove it
    if (files.length === 0) {
      core.debug(`Deleting ${parentDir}`)
      return fs.rmdir(parentDir)
    }
    return Promise.resolve(undefined)
  })
}

const removeMicromambaBinary = (options: Options) => {
  core.info('Removing micromamba binary ...')
  if (options.downloadMicromamba === false) {
    core.debug('Skipping micromamba binary removal.')
    return Promise.resolve(undefined)
  }
  core.debug(`Deleting ${options.micromambaBinPath}`)
  return fs.rm(options.micromambaBinPath, { force: false })
}

const removeAutoActivation = (options: Options) => {
  if (!options.createEnvironment) {
    core.debug('No environment created. Skipping removal of auto activation line.')
    return Promise.resolve(undefined)
  }
  return determineEnvironmentName(options.environmentName, options.environmentFile).then((environmentName) =>
    Promise.all(options.initShell.map((shell) => removeEnvironmentFromAutoActivate(options, environmentName, shell)))
  )
}

const cleanup = (options: Options) => {
  const postCleanup = options.postCleanup
  switch (postCleanup) {
    case 'none':
      return Promise.resolve(undefined)
    case 'shell-init':
      return Promise.all([
        removeMicromambaRunShell(options),
        ...options.initShell.map((shell) => shellDeinit(options, shell))
      ])
        .then(() => removeAutoActivation(options))
        .then(() => undefined) // output is not used
    case 'environment':
      return Promise.all([
        uninstallEnvironment(options),
        removeMicromambaRunShell(options),
        ...options.initShell.map((shell) => shellDeinit(options, shell))
      ])
        .then(() => removeAutoActivation(options))
        .then(() => undefined) // output is not used
    case 'all':
      return Promise.all(options.initShell.map((shell) => shellDeinit(options, shell)))
        .then(() =>
          // uninstallEnvironment is not called, because it is not needed if the root is removed
          Promise.all([
            removeRoot(options),
            removeMicromambaRunShell(options),
            removeMicromambaBinary(options),
            removeCustomCondarc(options)
          ])
        )
        .then(() => removeAutoActivation(options))
        .then(() => removeMicromambaBinaryParentIfEmpty(options))
    default:
      // This should never happen, because the input is validated in parseInputs
      throw new Error(`Unknown post cleanup type: ${postCleanup}`)
  }
}

const run = async () => {
  const options = getOptions()

  const cacheDownloadsCacheHit = JSON.parse(core.getState('cacheDownloadsCacheHit'))
  if (!cacheDownloadsCacheHit) {
    await saveCacheDownloads(options)
  }
  await cleanup(options)
}

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
