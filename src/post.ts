import * as fs from 'fs/promises'
import path from 'path'
import * as coreDefault from '@actions/core'
import { coreMocked } from './mocking'
import { parseInputs } from './inputs'
import type { Input } from './inputs'
import { PATHS, determineEnvironmentName } from './util'
import { shellDeinit } from './shell-init'

const core = process.env.MOCKING ? coreMocked : coreDefault

const removeMicromambaRunShell = (inputs: Input) => {
  if (!inputs.generateRunShell) {
    return Promise.resolve()
  }
  core.info('Removing micromamba run shell ...')
  return fs.unlink(PATHS.micromambaRunShell)
}

const uninstallEnvironment = (inputs: Input) => {
  return determineEnvironmentName(inputs.environmentName, inputs.environmentFile).then((environmentName) => {
    const envPath = path.join(PATHS.micromambaEnvs, environmentName)
    core.info(`Removing environment ${environmentName} ...`)
    core.debug(`Deleting ${envPath}`)
    return fs.rmdir(envPath, { recursive: true })
  })
}

const removePackages = () => {
  core.info('Removing packages ...')
  core.debug(`Deleting ${PATHS.micromambaPkgs}`)
  return fs.rmdir(PATHS.micromambaPkgs, { recursive: true })
}

const removeRoot = () => {
  core.info('Removing micromamba root ...')
  core.debug(`Deleting ${PATHS.micromambaRoot}`)
  return fs.rmdir(PATHS.micromambaRoot, { recursive: true })
}

const run = async () => {
  const inputs = parseInputs()
  // TODO: cache handling
  if (inputs.createEnvironment) {
    await removeMicromambaRunShell(inputs)
    await uninstallEnvironment(inputs)
  }
  await removePackages()
  await Promise.all(inputs.initShell.map((shell) => shellDeinit(shell, inputs)))
  await removeRoot()
}

run()
