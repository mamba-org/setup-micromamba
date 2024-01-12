import * as fs from 'fs/promises'
import * as os from 'os'
import path from 'path'
import * as coreDefault from '@actions/core'
import { coreMocked } from './mocking'
import { execute, mambaRegexBlock, micromambaCmd } from './util'
import { PATHS, getRootPrefixFlagForInit } from './options'
import type { ShellType, Options } from './options'

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

export const shellInit = (options: Options, shell: string) => {
  core.startGroup(`Initialize micromamba for ${shell}.`)
  const rootPrefixFlag = getRootPrefixFlagForInit(options)
  const command = execute(
    micromambaCmd(
      options,
      `shell init -s ${shell} ${rootPrefixFlag} ${options.micromambaRootPath}`,
      options.logLevel,
      options.condarcFile
    )
  )

  if (os.platform() === 'linux' && shell === 'bash') {
    return command.then(copyMambaInitBlockToBashProfile).finally(core.endGroup)
  }
  return command.finally(core.endGroup)
}

export const shellDeinit = (options: Options, shell: string) => {
  core.startGroup(`Deinitialize micromamba for ${shell}`)
  const rootPrefixFlag = getRootPrefixFlagForInit(options)
  const command = execute(
    micromambaCmd(
      options,
      `shell deinit -s ${shell} ${rootPrefixFlag} ${options.micromambaRootPath}`,
      options.logLevel,
      options.condarcFile
    )
  )
  if (os.platform() === 'linux' && shell === 'bash') {
    return command.then(removeMambaInitBlockFromBashProfile).finally(core.endGroup)
  }
  return command
}

const addEnvironmentToRcFile = (environmentName: string, rcFile: string) => {
  core.debug(`Adding \`micromamba activate ${environmentName}\n\` to ${rcFile}`)
  return fs.appendFile(rcFile, `micromamba activate ${environmentName}\n`)
}

const getRcFileDict = (options: Options) => ({
  bash: PATHS.bashProfile,
  zsh: path.join(os.homedir(), '.zshrc'),
  fish: path.join(os.homedir(), '.config', 'fish', 'config.fish'),
  tcsh: path.join(os.homedir(), '.tcshrc'),
  xonsh: path.join(os.homedir(), '.xonshrc'),
  'cmd.exe': path.join(options.micromambaRootPath, 'condabin', 'mamba_hook.bat'),
  powershell: path.join(os.homedir(), 'Documents', 'WindowsPowershell', 'profile.ps1'),
  pwshWin: path.join(os.homedir(), 'Documents', 'Powershell', 'profile.ps1'),
  pwshUnix: path.join(os.homedir(), '.config', 'powershell', 'profile.ps1')
})

const addEnvironmentToPowershellProfile = (options: Options, environmentName: string) => {
  const rcFileDict = getRcFileDict(options)

  // On GitHub Windows runners, powershell (the Windows version) and pwsh (the cross-platform version)
  // are both available. We need to add the environment to both profiles.
  switch (os.platform()) {
    case 'win32':
      return Promise.all([
        addEnvironmentToRcFile(environmentName, rcFileDict.powershell),
        addEnvironmentToRcFile(environmentName, rcFileDict.pwshWin)
      ]).then(() => undefined)
    case 'linux':
    case 'darwin':
      return addEnvironmentToRcFile(environmentName, rcFileDict.pwshUnix)
    default:
      throw new Error(`Unsupported platform: ${os.platform()}`)
  }
}

export const addEnvironmentToAutoActivate = (options: Options, environmentName: string, shell: ShellType) => {
  core.info(`Adding environment ${environmentName} to auto-activate ${shell} ...`)
  if (shell === 'powershell') {
    return addEnvironmentToPowershellProfile(options, environmentName)
  }

  const rcFilePath = getRcFileDict(options)[shell]
  core.debug(`Adding \`micromamba activate ${environmentName}\` to ${rcFilePath}`)
  return addEnvironmentToRcFile(environmentName, rcFilePath)
}

export const removeEnvironmentFromAutoActivate = (options: Options, environmentName: string, shell: ShellType) => {
  core.info(`Removing environment ${environmentName} from auto-activate ${shell} ...`)
  if (shell === 'powershell') {
    core.warning('powershell is not supported')
    return Promise.resolve(undefined)
  }

  const rcFilePath = getRcFileDict(options)[shell]

  return fs.readFile(rcFilePath, { encoding: 'utf-8' }).then((rcFile) => {
    const matches = rcFile.match(new RegExp(`micromamba activate ${environmentName}`))
    if (!matches) {
      throw new Error(`Could not find micromamba activate ${environmentName} in ${rcFilePath}`)
    }
    core.debug(`Removing micromamba activate ${environmentName} from ${rcFilePath}`)
    return fs.writeFile(rcFilePath, rcFile.replace(matches[0], ''))
  })
}
