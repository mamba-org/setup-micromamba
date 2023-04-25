import * as fs from 'fs/promises'
import * as os from 'os'
import path from 'path'
import * as coreDefault from '@actions/core'
import { coreMocked } from './mocking'
import { PATHS, options } from './options'
import { determineEnvironmentName } from './util'
import { shellDeinit } from './shell-init'

const core = process.env.MOCKING ? coreMocked : coreDefault

const removeMicromambaRunShell = () => {
  if (!options.generateRunShell || os.platform() === 'win32') {
    return Promise.resolve()
  }
  core.info('Removing micromamba run shell ...')
  return fs.rm(PATHS.micromambaRunShell)
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

const removeMicromambaBinary = () => {
  core.info('Removing micromamba binary ...')
  core.debug(`Deleting ${options.micromambaBinPath}`)
  // the micromamba binary may be in a different folder than the root
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
        .then(() => Promise.all([removeRoot(), removeMicromambaRunShell(), removeMicromambaBinary()]))
        .then(() => Promise.resolve())
    default:
      // This should never happen, because the input is validated in parseInputs
      throw new Error(`Unknown post cleanup type: ${postCleanup}`)
  }
}

const run = async () => {
  // TODO: cache handling
  await cleanup()
}

run()
