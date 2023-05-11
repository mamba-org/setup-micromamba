import fs from 'fs/promises'
import { constants as fsConstants } from 'fs' // fs.constants is not available in fs/promises for node < 18.4.0
import os from 'os'
import path from 'path'
import * as coreDefault from '@actions/core'
import * as io from '@actions/io'
import { downloadTool } from '@actions/tool-cache'
import { getMicromambaUrl, micromambaCmd, execute, determineEnvironmentName } from './util'
import { coreMocked } from './mocking'
import { PATHS, options } from './options'
import { addEnvironmentToAutoActivate, shellInit } from './shell-init'
import { restoreCacheDownloads, restoreCacheEnvironment, saveCacheEnvironment } from './cache'

const core = process.env.MOCKING ? coreMocked : coreDefault

const downloadMicromamba = (url: string) => {
  core.startGroup('Install micromamba')
  core.debug(`Downloading micromamba from ${url} ...`)

  return fs
    .mkdir(path.dirname(options.micromambaBinPath), { recursive: true })
    .then(() => downloadTool(url, options.micromambaBinPath))
    .then((_downloadPath) => fs.chmod(options.micromambaBinPath, 0o755))
    .then(() => core.info(`micromamba installed to ${options.micromambaBinPath}`))
    .catch((err) => {
      core.error(`Error installing micromamba: ${err.message}`)
      throw err
    })
    .finally(core.endGroup)
}

const generateCondarc = () => {
  if (!options.writeToCondarc) {
    core.debug(`Using condarc file ${options.condarcFile} ...`)
    return fs.access(options.condarcFile, fsConstants.R_OK)
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

const installEnvironment = () => {
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

const generateInfo = () => {
  core.startGroup('micromamba info')
  let command: Promise<number>
  if (!options.createEnvironment) {
    command = execute(micromambaCmd(`info -r ${options.micromambaRootPath}`))
  } else {
    command = determineEnvironmentName(options.environmentName, options.environmentFile).then((environmentName) =>
      execute(micromambaCmd(`info -r ${options.micromambaRootPath} -n ${environmentName}`))
    )
  }
  return command.finally(core.endGroup)
}

const generateMicromambaRunShell = () => {
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
chmod +x $1
$MAMBA_EXE run -r $MAMBA_ROOT_PREFIX -n $MAMBA_DEFAULT_ENV $1
`
  return determineEnvironmentName(options.environmentName, options.environmentFile)
    .then((environmentName) => {
      const file = micromambaRunShellContents
        .replace(/\$MAMBA_EXE/g, options.micromambaBinPath)
        .replace(/\$MAMBA_ROOT_PREFIX/g, options.micromambaRootPath)
        .replace(/\$MAMBA_DEFAULT_ENV/g, environmentName)
      core.debug(`Writing micromamba run shell to ${PATHS.micromambaRunShell}`)
      core.debug(`File contents:\n"${file}"`)
      return fs.writeFile(PATHS.micromambaRunShell, file, { encoding: 'utf8', mode: 0o755 })
    })
    .finally(core.endGroup)
}

const addEnvironmentPathToOutput = () => {
  return determineEnvironmentName(options.environmentName, options.environmentFile).then((environmentName) => {
    const environmentPath = path.join(options.micromambaRootPath, 'envs', environmentName)
    core.debug(`Setting environment-path output to ${environmentPath}`)
    core.setOutput('environment-path', environmentPath)
  })
}

const setEnvVariables = () => {
  core.info('Set environment variables.')
  core.debug(`MAMBA_ROOT_PREFIX: ${options.micromambaRootPath}`)
  core.exportVariable('MAMBA_ROOT_PREFIX', options.micromambaRootPath)
  core.debug(`MAMBA_EXE: ${options.micromambaBinPath}`)
  core.exportVariable('MAMBA_EXE', options.micromambaBinPath)
  core.debug(`CONDARC: ${options.condarcFile}`)
  core.exportVariable('CONDARC', options.condarcFile)
}

const run = async () => {
  core.debug(`process.env.HOME: ${process.env.HOME}`)
  core.debug(`os.homedir(): ${os.homedir()}`)
  core.debug(`bashProfile ${PATHS.bashProfile}`)

  if (process.platform === 'win32') {
    // Work around bug in Mamba: https://github.com/mamba-org/mamba/issues/1779
    // This prevents using setup-micromamba without bash
    core.addPath(path.dirname(await io.which('cygpath', true)))
  }

  await downloadMicromamba(getMicromambaUrl(options.micromambaSource))
  await generateCondarc()
  await Promise.all(options.initShell.map((shell) => shellInit(shell)))
  const cacheDownloadsKey = await restoreCacheDownloads()
  core.saveState('cacheDownloadsCacheHit', cacheDownloadsKey !== undefined)
  if (options.createEnvironment) {
    await installEnvironment()
    await generateMicromambaRunShell()
    await addEnvironmentPathToOutput()
  }
  setEnvVariables()
  await generateInfo()
}

run()
