import * as fs from 'fs/promises'
import * as os from 'os'
import * as coreDefault from '@actions/core'
import fetch from 'node-fetch'
import untildify from 'untildify'
import { PATHS, sha256, getMicromambaUrlFromInputs, micromambaCmd, execute } from './util'
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
  if (inputs.condarc) {
    core.info(`Writing condarc contents to ${PATHS.condarc} ...`)
    return fs.writeFile(PATHS.condarc, inputs.condarc)
  }
  core.info('Adding conda-forge to condarc channels ...')
  return fs.writeFile(PATHS.condarc, 'channels:\n  - conda-forge')
}

const createEnvironment = (inputs: Input) => {
  core.debug(`environmentFile: ${inputs.environmentFile}`)
  core.debug(`environmentName: ${inputs.environmentName}`)
  core.debug(`extraSpecs: ${inputs.extraSpecs}`)
  core.debug(`createArgs: ${inputs.createArgs}`)
  core.debug(`condarcFile: ${inputs.condarcFile}`)
  let commandStr = 'create -y'
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

const determineEnvironmentName = (inputs: Input) => {
  core.debug('Determining environment name from inputs.')
  if (inputs.environmentName) {
    core.debug(`Determined environment name: ${inputs.environmentName}`)
    return Promise.resolve(inputs.environmentName)
  }
  if (!inputs.environmentFile) {
    // This should never happen, because validateInputs should have thrown an error
    // TODO: make this prettier
    core.error('No environment name or file specified.')
    throw new Error()
  }
  return fs.readFile(inputs.environmentFile, 'utf8').then((fileContents) => {
    const environmentName = fileContents.toString().match(/name:\s*(.*)/)?.[1]
    if (!environmentName) {
      const errorMessage = `Could not determine environment name from file ${inputs.environmentFile}`
      core.error(errorMessage)
      throw new Error(errorMessage)
    }
    core.debug(`Determined environment name from file ${inputs.environmentFile}: ${environmentName}`)
    return environmentName
  })
}

const installEnvironment = (inputs: Input) => {
  return determineEnvironmentName(inputs)
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
  if (inputs.initShell.includes('bash')) {
    command = execute(['bash', '-eol', 'pipefail', '-c', `${micromambaCmd('info').join(' ')}`])
  } else if (inputs.initShell.includes('powershell')) {
    core.warning('Powershell is not supported yet.')
    command = execute(micromambaCmd('info'))
  } else if (inputs.initShell.includes('cmd.exe')) {
    core.warning('cmd.exe is not supported yet.')
    command = execute(micromambaCmd('info'))
  } else {
    command = execute(micromambaCmd('info'))
  }
  return command.finally(core.endGroup)
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
  }
  await generateInfo(inputs)
}

run()
