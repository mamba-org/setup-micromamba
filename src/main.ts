import * as fs from 'fs/promises'
import * as os from 'os'
import * as coreDefault from '@actions/core'
import fetch from 'node-fetch'
import untildify from 'untildify'
import { PATHS, sha256, getMicromambaUrlFromInputs, micromambaCmd, execute, determineEnvironmentName } from './util'
import { coreMocked } from './mocking'
import { getOptions } from './inputs'
import type { Options } from './inputs'
import { addEnvironmentToAutoActivate, shellInit } from './shell-init'

const core = process.env.MOCKING ? coreMocked : coreDefault

const downloadMicromamba = (url: string) => {
  core.startGroup('Install micromamba')
  core.debug(`Downloading micromamba from ${url} ...`)

  const mkDir = fs.mkdir(PATHS.micromambaBinFolder, { recursive: true })
  const downloadMicromamba = fetch(url)
    .then((res) => {
      if (!res.ok) {
        throw new Error(`Download failed: ${res.statusText}`)
      }
      return res.arrayBuffer()
    })
    .then((arrayBuffer) => Buffer.from(arrayBuffer))

  return Promise.all([mkDir, downloadMicromamba])
    .then(([, buffer]) => {
      core.debug(`micromamba binary sha256: ${sha256(buffer)}`)
      return fs.writeFile(PATHS.micromambaBin, buffer, { encoding: 'binary', mode: 0o755 })
    })
    .then(() => {
      core.info(`micromamba installed to ${PATHS.micromambaBin}`)
    })
    .catch((err) => {
      core.error(`Error installing micromamba: ${err.message}`)
      throw err
    })
    .finally(core.endGroup)
}

const generateCondarc = (options: Options) => {
  if (options.condarcFile) {
    core.debug(`Using condarc file ${options.condarcFile} ...`)
    return fs.access(untildify(options.condarcFile), fs.constants.F_OK)
  }
  core.debug(`Using ${PATHS.condarc} as condarc file.`)
  options.condarcFile = PATHS.condarc
  const mkDir = fs.mkdir(PATHS.micromambaRoot, { recursive: true })
  // if we don't put this into a variable, the compiler complains
  const condarcFile = options.condarcFile
  if (options.condarc) {
    core.info(`Writing condarc contents to ${options.condarcFile} ...`)
    const condarc = options.condarc
    return mkDir.then(() => fs.writeFile(condarcFile, condarc))
  }
  core.info('Adding conda-forge to condarc channels ...')
  return mkDir.then(() => fs.writeFile(condarcFile, 'channels:\n  - conda-forge'))
}

const createEnvironment = (options: Options) => {
  core.debug(`environmentFile: ${options.environmentFile}`)
  core.debug(`environmentName: ${options.environmentName}`)
  core.debug(`extraSpecs: ${options.extraSpecs}`)
  core.debug(`createArgs: ${options.createArgs}`)
  core.debug(`condarcFile: ${options.condarcFile}`)
  let commandStr = `create -y -r ${PATHS.micromambaRoot}`
  if (options.environmentFile) {
    commandStr += ` -f ${options.environmentFile}`
  }
  if (options.environmentName) {
    commandStr += ` -n ${options.environmentName}`
  }
  if (options.extraSpecs) {
    console.log(`EXTRASPECS ${options.extraSpecs}`)
    commandStr += ` ${options.extraSpecs.join(' ')}`
  }
  if (options.createArgs) {
    commandStr += ` ${options.createArgs}`
  }
  if (options.condarcFile) {
    commandStr += ` --rc-file ${options.condarcFile}`
  }
  return execute(micromambaCmd(commandStr, options.logLevel, options.condarcFile))
}

const installEnvironment = (options: Options) => {
  return determineEnvironmentName(options.environmentName, options.environmentFile)
    .then((environmentName) => {
      core.startGroup(`Install environment \`${environmentName}\``)
      return createEnvironment(options).then((_exitCode) => environmentName)
    })
    .then((environmentName) => {
      return Promise.all(options.initShell.map((shell) => addEnvironmentToAutoActivate(environmentName, shell)))
    })
    .finally(core.endGroup)
}

const generateInfo = (options: Options) => {
  core.startGroup('micromamba info')
  let command: Promise<number>
  if (!options.createEnvironment) {
    command = execute(micromambaCmd(`info -r ${PATHS.micromambaRoot}`))
  } else {
    command = determineEnvironmentName(options.environmentName, options.environmentFile).then((environmentName) =>
      execute(micromambaCmd(`info -r ${PATHS.micromambaRoot} -n ${environmentName}`))
    )
  }
  return command.finally(core.endGroup)
}

const generateMicromambaRunShell = (options: Options) => {
  if (!options.generateRunShell) {
    core.debug('Skipping micromamba run shell generation.')
    return Promise.resolve()
  }
  if (os.platform() === 'win32') {
    core.info('Skipping micromamba run shell on Windows.')
    return Promise.resolve()
  }
  core.info('Generating micromamba run shell.')
  const micromambaShellFile = fs.readFile('src/resources/micromamba-shell', { encoding: 'utf8' })
  return Promise.all([micromambaShellFile, determineEnvironmentName(options.environmentName, options.environmentFile)])
    .then(([fileContents, environmentName]) => {
      const file = fileContents
        .replace(/\$MAMBA_EXE/g, PATHS.micromambaBin)
        .replace(/\$MAMBA_ROOT_PREFIX/g, PATHS.micromambaRoot)
        .replace(/\$MAMBA_DEFAULT_ENV/g, environmentName)
      return fs.writeFile(PATHS.micromambaRunShell, file, { encoding: 'utf8', mode: 0o755 })
    })
    .finally(core.endGroup)
}

const run = async () => {
  core.debug(`process.env.HOME: ${process.env.HOME}`)
  core.debug(`os.homedir(): ${os.homedir()}`)
  core.debug(`bashProfile ${PATHS.bashProfile}`)
  core.debug(core.getInput('extra-specs'))
  const options = getOptions()

  const url = getMicromambaUrlFromInputs(options.micromambaVersion, options.micromambaUrl)
  await downloadMicromamba(url)
  await generateCondarc(options)
  await Promise.all(options.initShell.map((shell) => shellInit(shell, options)))
  if (options.createEnvironment) {
    await installEnvironment(options)
    await generateMicromambaRunShell(options)
  }
  await generateInfo(options)
}

run()
