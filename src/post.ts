import * as fs from 'fs/promises'
import * as os from 'os'
import path from 'path'
import * as coreDefault from '@actions/core'
import { coreMocked } from './mocking'
import { getOptions } from './inputs'
import type { Options } from './inputs'
import { PATHS, determineEnvironmentName } from './util'
import { shellDeinit } from './shell-init'

const core = process.env.MOCKING ? coreMocked : coreDefault

const removeMicromambaRunShell = (inputs: Options) => {
  if (!inputs.generateRunShell || os.platform() === 'win32') {
    return Promise.resolve()
  }
  core.info('Removing micromamba run shell ...')
  return fs.rm(PATHS.micromambaRunShell)
}

const uninstallEnvironment = (options: Options) => {
  return determineEnvironmentName(options.environmentName, options.environmentFile).then((environmentName) => {
    const envPath = path.join(PATHS.micromambaRoot, 'envs', environmentName)
    core.info(`Removing environment ${environmentName} ...`)
    core.debug(`Deleting ${envPath}`)
    return fs.rm(envPath, { recursive: true })
  })
}

const removeRoot = () => {
  core.info('Removing micromamba root ...')
  core.debug(`Deleting ${PATHS.micromambaRoot}`)
  return fs.rm(PATHS.micromambaRoot, { recursive: true })
}

const removeMicromambaBinary = () => {
  core.info('Removing micromamba binary ...')
  core.debug(`Deleting ${PATHS.micromambaBin}`)
  // the micromamba binary may be in a different folder than the root
  return fs.rm(PATHS.micromambaBin, { force: false })
}

const cleanup = (options: Options) => {
  const postCleanup = options.postCleanup
  switch (postCleanup) {
    case 'none':
      return Promise.resolve()
    case 'shell-init':
      return Promise.all([
        removeMicromambaRunShell(options),
        ...options.initShell.map((shell) => shellDeinit(shell, options))
      ]).then(() => Promise.resolve()) // output is not used
    case 'environment':
      return Promise.all([
        uninstallEnvironment(options),
        removeMicromambaRunShell(options),
        ...options.initShell.map((shell) => shellDeinit(shell, options))
      ]).then(() => Promise.resolve())
    case 'all':
      return Promise.all(options.initShell.map((shell) => shellDeinit(shell, options)))
        .then(() => Promise.all([removeRoot(), removeMicromambaRunShell(options), removeMicromambaBinary()]))
        .then(() => Promise.resolve())
    default:
      // This should never happen, because the input is validated in parseInputs
      throw new Error(`Unknown post cleanup type: ${postCleanup}`)
  }
}

const run = async () => {
  const options = getOptions()
  // TODO: cache handling
  await cleanup(options)
}

run()
