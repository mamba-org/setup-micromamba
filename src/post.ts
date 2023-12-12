import * as fs from 'fs/promises'
import * as os from 'os'
import path from 'path'
import { options } from './options'
import { determineEnvironmentName } from './util'
import { shellDeinit } from './shell-init'
import { saveCacheDownloads } from './cache'
import { core } from './core'

const removeMicromambaRunShell = () => {
  if (!options.generateRunShell || os.platform() === 'win32') {
    return Promise.resolve()
  }
  core.info('Removing micromamba run shell ...')
  return fs.rm(options.micromambaRunShellPath)
}

const uninstallEnvironment = () => {
  return determineEnvironmentName(options.environmentName, options.environmentFile).then((environmentName) => {
    const envPath = path.join(options.micromambaRootPath, 'envs', environmentName)
    core.info(`Removing environment ${environmentName} ...`)
    core.debug(`Deleting ${envPath}`)
    return fs.rm(envPath, { recursive: true })
  })
}

const removeRoot = () => {
  core.info('Removing micromamba root ...')
  core.debug(`Deleting ${options.micromambaRootPath}`)
  return fs.rm(options.micromambaRootPath, { recursive: true })
}

const removeCustomCondarc = () => {
  if (!options.writeToCondarc) {
    return Promise.resolve()
  }
  core.info('Removing custom condarc ...')
  core.debug(`Deleting ${options.condarcFile}`)
  return fs.rm(options.condarcFile)
}

const removeMicromambaBinaryParentIfEmpty = () => {
  const parentDir = path.dirname(options.micromambaBinPath)
  return fs.readdir(parentDir).then((files) => {
    // if the folder is empty, remove it
    if (files.length === 0) {
      core.debug(`Deleting ${parentDir}`)
      return fs.rmdir(parentDir)
    }
    return Promise.resolve()
  })
}

const removeMicromambaBinary = () => {
  core.info('Removing micromamba binary ...')
  if (options.downloadMicromamba === false) {
    core.debug('Skipping micromamba binary removal.')
    return Promise.resolve()
  }
  core.debug(`Deleting ${options.micromambaBinPath}`)
  return fs.rm(options.micromambaBinPath, { force: false })
}

const cleanup = () => {
  const postCleanup = options.postCleanup
  switch (postCleanup) {
    case 'none':
      return Promise.resolve()
    case 'shell-init':
      return Promise.all([removeMicromambaRunShell(), ...options.initShell.map((shell) => shellDeinit(shell))]).then(
        () => Promise.resolve()
      ) // output is not used
    case 'environment':
      return Promise.all([
        uninstallEnvironment(),
        removeMicromambaRunShell(),
        ...options.initShell.map((shell) => shellDeinit(shell))
      ]).then(() => Promise.resolve())
    case 'all':
      return Promise.all(options.initShell.map((shell) => shellDeinit(shell)))
        .then(() =>
          // uninstallEnvironment is not called, because it is not needed if the root is removed
          Promise.all([removeRoot(), removeMicromambaRunShell(), removeMicromambaBinary(), removeCustomCondarc()])
        )
        .then(removeMicromambaBinaryParentIfEmpty)
    default:
      // This should never happen, because the input is validated in parseInputs
      throw new Error(`Unknown post cleanup type: ${postCleanup}`)
  }
}

const run = async () => {
  const cacheDownloadsCacheHit = JSON.parse(core.getState('cacheDownloadsCacheHit'))
  if (!cacheDownloadsCacheHit) {
    await saveCacheDownloads()
  }
  await cleanup()
}

run()
