import * as fs from 'fs/promises'
import * as os from 'os'
import path from 'path'
import * as coreDefault from '@actions/core'
import { coreMocked } from './mocking'
import { PostCleanupType, parseInputs } from './inputs'
import type { Input } from './inputs'
import { PATHS, determineEnvironmentName } from './util'
import { shellDeinit } from './shell-init'

const core = process.env.MOCKING ? coreMocked : coreDefault

const removeMicromambaRunShell = (inputs: Input) => {
  if (!inputs.generateRunShell || os.platform() === 'win32') {
    return Promise.resolve()
  }
  core.info('Removing micromamba run shell ...')
  return fs.rm(PATHS.micromambaRunShell)
}

const uninstallEnvironment = (inputs: Input) => {
  return determineEnvironmentName(inputs.environmentName, inputs.environmentFile).then((environmentName) => {
    const envPath = path.join(PATHS.micromambaEnvs, environmentName)
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

const cleanup = (inputs: Input) => {
  const postCleanup = inputs.postCleanup
  switch (postCleanup) {
    case 'none':
      return Promise.resolve()
    case 'shell-init':
      return Promise.all([
        removeMicromambaRunShell(inputs),
        ...inputs.initShell.map((shell) => shellDeinit(shell, inputs))
      ]).then(() => Promise.resolve()) // output is not used
    case 'environment':
      return Promise.all([
        uninstallEnvironment(inputs),
        removeMicromambaRunShell(inputs),
        ...inputs.initShell.map((shell) => shellDeinit(shell, inputs))
      ]).then(() => Promise.resolve())
    case 'all':
      return Promise.all(inputs.initShell.map((shell) => shellDeinit(shell, inputs)))
        .then(() => Promise.all([removeRoot(), removeMicromambaRunShell(inputs), removeMicromambaBinary()]))
        .then(() => Promise.resolve())
    default:
      // This should never happen, because the input is validated in parseInputs
      throw new Error(`Unknown post cleanup type: ${postCleanup}`)
  }
}

const run = async () => {
  const inputs = parseInputs()
  // TODO: cache handling
  await cleanup(inputs)
}

run()
