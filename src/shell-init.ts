import * as fs from 'fs/promises'
import * as os from 'os'
import path from 'path'
import * as coreDefault from '@actions/core'
import { coreMocked } from './mocking'
import { PATHS, execute, mambaRegexBlock, micromambaCmd } from './util'
import type { Input, ShellType } from './inputs'

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

export const shellInit = (shell: string, inputs: Input) => {
  core.startGroup(`Initialize micromamba for ${shell}`)
  const command = execute(micromambaCmd(`shell init -s ${shell}`, inputs.logLevel, inputs.condarcFile))
  if (os.platform() === 'linux' && shell === 'bash') {
    return command.then(copyMambaInitBlockToBashProfile).finally(core.endGroup)
  }
  return command.finally(core.endGroup)
}

export const shellDeinit = (shell: string, inputs: Input) => {
  core.startGroup(`Deinitialize micromamba for ${shell}`)
  const command = execute(micromambaCmd(`shell deinit -s ${shell}`, inputs.logLevel, inputs.condarcFile))
  if (os.platform() === 'linux' && shell === 'bash') {
    return command.then(removeMambaInitBlockFromBashProfile)
  }
  return command
}

const addEnvironmentToRcFile = (environmentName: string, rcFile: string) => {
  return fs.appendFile(rcFile, `micromamba activate ${environmentName}\n`)
}

const rcFileDict = {
  bash: PATHS.bashProfile,
  zsh: path.join(os.homedir(), '.zshrc'),
  fish: path.join(os.homedir(), '.config', 'fish', 'config.fish'),
  tcsh: path.join(os.homedir(), '.tcshrc'),
  xonsh: path.join(os.homedir(), '.xonshrc')
}

export const addEnvironmentToAutoActivate = (environmentName: string, shell: ShellType) => {
  core.info(`Adding environment ${environmentName} to auto-activate ${shell} ...`)
  if (shell === 'cmd.exe') {
    core.warning('cmd.exe is not supported')
    return Promise.resolve()
  }
  if (shell === 'powershell') {
    core.warning('powershell is not supported')
    return Promise.resolve()
  }
  return addEnvironmentToRcFile(environmentName, rcFileDict[shell])
}

export const removeEnvironmentFromAutoActivate = (environmentName: string, shell: ShellType) => {
  core.info(`Removing environment ${environmentName} from auto-activate ${shell} ...`)
  if (shell === 'cmd.exe') {
    core.warning('cmd.exe is not supported')
    return Promise.resolve()
  }
  if (shell === 'powershell') {
    core.warning('powershell is not supported')
    return Promise.resolve()
  }
  return fs.readFile(rcFileDict[shell], { encoding: 'utf-8' }).then((rcFile) => {
    const matches = rcFile.match(new RegExp(`micromamba activate ${environmentName}`))
    if (!matches) {
      throw new Error(`Could not find micromamba activate ${environmentName} in ${rcFileDict[shell]}`)
    }
    core.debug(`Removing micromamba activate ${environmentName} from ${rcFileDict[shell]}`)
    return fs.writeFile(rcFileDict[shell], rcFile.replace(matches[0], ''))
  })
}
