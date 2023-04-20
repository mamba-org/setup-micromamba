import * as fs from 'fs/promises'
import * as os from 'os'
import * as coreDefault from '@actions/core'
import fetch from 'node-fetch'
import untildify from 'untildify'
import { PATHS, sha256, getMicromambaUrlFromInputs, micromambaCmd, execute, determineEnvironmentName } from './util'
import { coreMocked } from './mocking'
import { parseInputs, validateInputs } from './inputs'
import type { Input } from './inputs'
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

const generateCondarc = (inputs: Input) => {
  if (inputs.condarcFile) {
    core.debug(`Using condarc file ${inputs.condarcFile} ...`)
    return fs.access(untildify(inputs.condarcFile), fs.constants.F_OK)
  }
  core.debug(`Using ${PATHS.condarc} as condarc file.`)
  inputs.condarcFile = PATHS.condarc
  const mkDir = fs.mkdir(PATHS.micromambaRoot, { recursive: true })
  // if we don't put this into a variable, the compiler complains
  const condarcFile = inputs.condarcFile
  if (inputs.condarc) {
    core.info(`Writing condarc contents to ${inputs.condarcFile} ...`)
    const condarc = inputs.condarc
    return mkDir.then(() => fs.writeFile(condarcFile, condarc))
  }
  core.info('Adding conda-forge to condarc channels ...')
  return mkDir.then(() => fs.writeFile(condarcFile, 'channels:\n  - conda-forge'))
}

const createEnvironment = (inputs: Input) => {
  core.debug(`environmentFile: ${inputs.environmentFile}`)
  core.debug(`environmentName: ${inputs.environmentName}`)
  core.debug(`extraSpecs: ${inputs.extraSpecs}`)
  core.debug(`createArgs: ${inputs.createArgs}`)
  core.debug(`condarcFile: ${inputs.condarcFile}`)
  let commandStr = `create -y -r ${PATHS.micromambaRoot}`
  if (inputs.environmentFile) {
    commandStr += ` -f ${inputs.environmentFile}`
  }
  if (inputs.environmentName) {
    commandStr += ` -n ${inputs.environmentName}`
  }
  if (inputs.extraSpecs) {
    console.log(`EXTRASPECS ${inputs.extraSpecs}`)
    commandStr += ` ${inputs.extraSpecs.join(' ')}`
  }
  if (inputs.createArgs) {
    commandStr += ` ${inputs.createArgs}`
  }
  if (inputs.condarcFile) {
    commandStr += ` --rc-file ${inputs.condarcFile}`
  }
  return execute(micromambaCmd(commandStr, inputs.logLevel, inputs.condarcFile))
}

const installEnvironment = (inputs: Input) => {
  return determineEnvironmentName(inputs.environmentName, inputs.environmentFile)
    .then((environmentName) => {
      core.startGroup(`Install environment \`${environmentName}\``)
      return createEnvironment(inputs).then((_exitCode) => environmentName)
    })
    .then((environmentName) => {
      return Promise.all(inputs.initShell.map((shell) => addEnvironmentToAutoActivate(environmentName, shell)))
    })
    .finally(core.endGroup)
}

const generateInfo = (inputs: Input) => {
  core.startGroup('micromamba info')
  let command: Promise<number>
  if (!inputs.createEnvironment) {
    command = execute(micromambaCmd(`info -r ${PATHS.micromambaRoot}`))
  } else {
    command = determineEnvironmentName(inputs.environmentName, inputs.environmentFile).then((environmentName) =>
      execute(micromambaCmd(`info -r ${PATHS.micromambaRoot} -n ${environmentName}`))
    )
  }
  return command.finally(core.endGroup)
}

const generateMicromambaRunShell = (inputs: Input) => {
  if (!inputs.generateRunShell) {
    core.debug('Skipping micromamba run shell generation.')
    return Promise.resolve()
  }
  if (os.platform() === 'win32') {
    core.info('Skipping micromamba run shell on Windows.')
    return Promise.resolve()
  }
  core.info('Generating micromamba run shell.')
  const micromambaShellFile = fs.readFile('src/resources/micromamba-shell', { encoding: 'utf8' })
  return Promise.all([micromambaShellFile, determineEnvironmentName(inputs)])
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
  const inputs = parseInputs()
  core.debug(`Parsed inputs: ${JSON.stringify(inputs, null, 2)}`)
  validateInputs(inputs)

  const url = getMicromambaUrlFromInputs(inputs.micromambaUrl, inputs.micromambaVersion)
  await downloadMicromamba(url)
  await generateCondarc(inputs)
  await Promise.all(inputs.initShell.map((shell) => shellInit(shell, inputs)))
  if (inputs.createEnvironment) {
    await installEnvironment(inputs)
    // TODO: delete micromamba-shell in post step
    await generateMicromambaRunShell(inputs)
  }
  await generateInfo(inputs)
}

run()
