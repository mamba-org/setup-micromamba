import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { downloadTool } from '@actions/tool-cache'
import { micromambaCmd, execute, determineEnvironmentName } from './util'
import { options } from './options'
import { addEnvironmentToAutoActivate } from './shell-init'
import { restoreCacheEnvironment, saveCacheEnvironment } from './cache'
import { core } from './core'

export const downloadMicromamba = (url: string) => {
  if (options.downloadMicromamba === false) {
    core.info('Skipping micromamba download.')
    core.addPath(path.dirname(options.micromambaBinPath))
    return Promise.resolve()
  }
  core.startGroup('Install micromamba')
  core.debug(`Downloading micromamba from ${url} ...`)

  return fs
    .mkdir(path.dirname(options.micromambaBinPath), { recursive: true })
    .then(() => downloadTool(url, options.micromambaBinPath))
    .then((_downloadPath) => fs.chmod(options.micromambaBinPath, 0o755))
    .then(() => core.addPath(path.dirname(options.micromambaBinPath)))
    .then(() => core.info(`micromamba installed to ${options.micromambaBinPath}`))
    .catch((err) => {
      core.error(`Error installing micromamba: ${err.message}`)
      throw err
    })
    .finally(core.endGroup)
}

export const generateCondarc = () => {
  if (!options.writeToCondarc) {
    core.debug(`Using condarc file ${options.condarcFile} ...`)
    return fs.access(options.condarcFile, fs.constants.R_OK)
  }
  core.debug(`Using ${options.condarcFile} as condarc file.`)
  const mkDir = fs.mkdir(path.dirname(options.condarcFile), { recursive: true })
  if (options.condarc) {
    core.info(`Writing condarc contents to ${options.condarcFile} ...`)
    // if we don't put this into a variable, typescript complains
    const condarc = options.condarc
    return mkDir.then(() => fs.writeFile(options.condarcFile, condarc))
  }
  // default: condarc contains conda-forge channel
  core.info('Adding conda-forge to condarc channels ...')
  return mkDir.then(() => fs.writeFile(options.condarcFile, 'channels:\n  - conda-forge'))
}

const createEnvironment = () => {
  core.debug(`environmentFile: ${options.environmentFile}`)
  core.debug(`environmentName: ${options.environmentName}`)
  core.debug(`createArgs: ${options.createArgs}`)
  core.debug(`condarcFile: ${options.condarcFile}`)
  let commandStr = `create -y -r ${options.micromambaRootPath}`
  if (options.environmentFile) {
    commandStr += ` -f ${options.environmentFile}`
  }
  if (options.environmentName) {
    commandStr += ` -n ${options.environmentName}`
  }
  if (options.createArgs) {
    commandStr += ` ${options.createArgs.join(' ')}`
  }
  return execute(micromambaCmd(commandStr, options.logLevel, options.condarcFile))
}

export const installEnvironment = () => {
  return determineEnvironmentName(options.environmentName, options.environmentFile)
    .then((environmentName) =>
      Promise.all([Promise.resolve(environmentName), restoreCacheEnvironment(environmentName)])
    )
    .then(([environmentName, cacheKey]) => {
      if (cacheKey) {
        // cache hit, no need to install and save cache
        return Promise.resolve(environmentName)
      }
      // cache miss, install and save cache
      core.startGroup(`Install environment \`${environmentName}\``)
      return createEnvironment()
        .then((_exitCode) => {
          core.endGroup()
          return environmentName
        })
        .then((environmentName) =>
          // cache can already be saved here and not in post action since the environment is not changing anymore
          saveCacheEnvironment(environmentName).then(() => environmentName)
        )
    })
    .then((environmentName) =>
      Promise.all(options.initShell.map((shell) => addEnvironmentToAutoActivate(environmentName, shell)))
    )
}

export const generateInfo = () => {
  core.startGroup('micromamba info')
  let command: Promise<number>
  if (!options.createEnvironment) {
    command = execute(micromambaCmd(`info -r ${options.micromambaRootPath}`))
  } else {
    command = determineEnvironmentName(options.environmentName, options.environmentFile)
      .then((environmentName) =>
        Promise.all([
          execute(micromambaCmd(`info -r ${options.micromambaRootPath} -n ${environmentName}`)),
          Promise.resolve(environmentName)
        ])
      )
      .then(([_exitCode, environmentName]) => {
        core.endGroup()
        core.startGroup('micromamba list')
        return execute(micromambaCmd(`list -r ${options.micromambaRootPath} -n ${environmentName}`))
      })
  }
  return command.finally(core.endGroup)
}

export const generateMicromambaRunShell = () => {
  if (!options.generateRunShell) {
    core.debug('Skipping micromamba run shell generation.')
    return Promise.resolve()
  }
  if (os.platform() === 'win32') {
    core.info('Skipping micromamba run shell on Windows.')
    return Promise.resolve()
  }
  core.info('Generating micromamba run shell.')
  const micromambaRunShellContents = `#!/usr/bin/env sh
if test -f "$1"; then chmod +x $1; fi
$MAMBA_EXE run -r $MAMBA_ROOT_PREFIX -n $MAMBA_DEFAULT_ENV "$@"
`
  return determineEnvironmentName(options.environmentName, options.environmentFile)
    .then((environmentName) => {
      const file = micromambaRunShellContents
        .replace(/\$MAMBA_EXE/g, options.micromambaBinPath)
        .replace(/\$MAMBA_ROOT_PREFIX/g, options.micromambaRootPath)
        .replace(/\$MAMBA_DEFAULT_ENV/g, environmentName)
      core.debug(`Writing micromamba run shell to ${options.micromambaRunShellPatu}`)
      core.debug(`File contents:\n"${file}"`)
      return fs.writeFile(options.micromambaRunShellPath, file, { encoding: 'utf8', mode: 0o755 })
    })
    .finally(core.endGroup)
}
