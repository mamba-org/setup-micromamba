import * as fs from 'fs/promises'
import * as os from 'os'
import * as coreDefault from '@actions/core'
import { coreMocked } from './mocking'
import { PATHS, execute, mambaRegexBlock, micromambaCmd } from './util'
import type { LogLevelType } from './inputs'

const core = process.env.MOCKING ? coreMocked : coreDefault

const copyMambaInitBlockToBashProfile = () => {
  // By default, micromamba adds the shell hooks to the .bashrc file.
  // This is not the desired behavior for CI, so we need to move this
  // to the .bash_profile file.
  core.info('Moving mamba initialize block to .bash_profile')
  return fs.readFile(PATHS.bashrc, { encoding: 'utf-8' }).then((bashrc) => {
    const matches = bashrc.match(mambaRegexBlock)
    if (!matches) {
      throw new Error('Could not find mamba initialization block in .bashrc')
    }
    core.debug(`Adding mamba initialization block to .bash_profile: ${matches[0]}`)
    return fs.appendFile(PATHS.bashProfile, matches[0])
  })
}

const removeMambaInitBlockFromBashProfile = () => {
  core.info('Removing mamba initialize block from .bash_profile')
  return fs.readFile(PATHS.bashProfile, { encoding: 'utf-8' }).then((bashProfile) => {
    const matches = bashProfile.match(mambaRegexBlock)
    if (!matches) {
      throw new Error('Could not find mamba initialization block in .bash_profile')
    }
    core.debug(`Removing mamba initialization block from .bash_profile: ${matches[0]}`)
    return fs.writeFile(PATHS.bashProfile, bashProfile.replace(mambaRegexBlock, ''))
  })
}

export const shellInit = (shell: string, logLevel: LogLevelType) => {
  core.startGroup(`Initialize micromamba for ${shell}`)
  const command = execute(micromambaCmd(`shell init -s ${shell}`, logLevel))
  if (os.platform() === 'linux' && shell === 'bash') {
    return command.then(copyMambaInitBlockToBashProfile)
  }
  return command
}

export const shellDeinit = (shell: string, logLevel: LogLevelType) => {
  core.startGroup(`Deinitialize micromamba for ${shell}`)
  const command = execute(micromambaCmd(`shell deinit -s ${shell}`, logLevel))
  if (os.platform() === 'linux' && shell === 'bash') {
    return command.then(removeMambaInitBlockFromBashProfile)
  }
  return command
}
