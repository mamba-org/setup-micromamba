import * as path from 'path'
import * as os from 'os'
import { exit } from 'process'
import * as coreDefault from '@actions/core'
import * as z from 'zod'
import { left, right } from 'fp-ts/lib/Either'
import type { Either } from 'fp-ts/lib/Either'
import untildify from 'untildify'
import which from 'which'
import { coreMocked } from './mocking'
import { getTempDirectory } from './util'

const core = process.env.MOCKING ? coreMocked : coreDefault

export const PATHS = {
  micromambaBin: path.join(os.homedir(), 'micromamba-bin', `micromamba${os.platform() === 'win32' ? '.exe' : ''}`),
  micromambaRoot: path.join(os.homedir(), 'micromamba'),
  bashProfile: path.join(os.homedir(), '.bash_profile'),
  bashrc: path.join(os.homedir(), '.bashrc')
}

type Inputs = Readonly<{
  condarcFile?: string
  condarc?: string
  environmentFile?: string
  environmentName?: string
  createArgs?: string[]
  logLevel?: LogLevelType
  micromambaVersion?: string
  micromambaUrl?: string
  downloadMicromamba?: boolean
  initShell?: ShellTypeWithNone[]
  generateRunShell?: boolean
  cacheDownloads?: boolean
  cacheDownloadsKey?: string
  cacheEnvironment?: boolean
  cacheEnvironmentKey?: string
  postCleanup?: PostCleanupType
  micromambaRootPath?: string
  micromambaBinPath?: string
}>

export type Options = Readonly<{
  writeToCondarc: boolean
  condarcFile: string
  condarc?: string
  createEnvironment: boolean
  environmentFile?: string
  environmentName?: string
  createArgs: string[]
  logLevel: LogLevelType
  micromambaSource: MicromambaSourceType
  downloadMicromamba: boolean
  initShell: ShellType[]
  generateRunShell: boolean
  cacheDownloadsKey?: string // undefined if cacheDownloads is false
  cacheEnvironmentKey?: string // undefined if cacheEnvironment is false
  postCleanup: PostCleanupType
  micromambaRootPath: string
  micromambaBinPath: string
  micromambaRunShellPath: string
}>

const postCleanupSchema = z.enum(['none', 'shell-init', 'environment', 'all'])
export type PostCleanupType = z.infer<typeof postCleanupSchema>

const logLevelSchema = z.enum(['off', 'critical', 'error', 'warning', 'info', 'debug', 'trace'])
export type LogLevelType = z.infer<typeof logLevelSchema>

const shellSchema = z.enum(['none', 'bash', 'cmd.exe', 'fish', 'powershell', 'tcsh', 'xonsh', 'zsh'])
type ShellTypeWithNone = z.infer<typeof shellSchema>
export type ShellType = Exclude<ShellTypeWithNone, 'none'>

export type MicromambaSourceType = Either<string, string> // Either<version, url>

const parseOrUndefined = <T>(key: string, schema: z.ZodSchema<T>, errorMessage?: string): T | undefined => {
  const input = core.getInput(key)
  // GitHub actions sets empty inputs to the empty string, but we want undefined
  if (input === '') {
    return undefined
  }
  const maybeResult = schema.safeParse(input)
  if (!maybeResult.success) {
    if (!errorMessage) {
      throw new Error(`${key} is not valid: ${maybeResult.error.message}`)
    }
    throw new Error(errorMessage)
  }
  return maybeResult.data
}

const parseOrUndefinedJSON = <T>(key: string, schema: z.ZodSchema<T>): T | undefined => {
  const input = core.getInput(key)
  // GitHub actions sets empty inputs to the empty string, but we want undefined
  if (input === '') {
    return undefined
  }
  return schema.parse(JSON.parse(input))
}

const parseOrUndefinedList = <T>(key: string, schema: z.ZodSchema<T>): T[] | undefined => {
  const input = core.getInput(key)
  // GitHub actions sets empty inputs to the empty string, but we want undefined
  if (input === '') {
    return undefined
  }
  return input
    .split(' ')
    .map((s) => schema.parse(s))
    .filter((s) => s !== '')
}

const determineMicromambaInstallation = (micromambaBinPath?: string, downloadMicromamba?: boolean) => {
  const preinstalledMicromamba = which.sync('micromamba', { nothrow: true })
  if (preinstalledMicromamba) {
    core.debug(`Found pre-installed micromamba at ${preinstalledMicromamba}`)
  }

  if (micromambaBinPath) {
    core.debug(`Using micromamba binary path ${micromambaBinPath}`)

    try {
      const resolvedPath = path.resolve(untildify(micromambaBinPath))
      return { downloadMicromamba: downloadMicromamba !== false, micromambaBinPath: resolvedPath }
    } catch (error) {
      throw new Error(`Could not resolve micromamba binary path ${micromambaBinPath}`)
    }
  }

  if (downloadMicromamba === false && !preinstalledMicromamba) {
    throw new Error('Could not find a pre-installed micromamba installation and `download-micromamba` is false.')
  }

  if (!downloadMicromamba && preinstalledMicromamba) {
    return { downloadMicromamba: false, micromambaBinPath: preinstalledMicromamba }
  }

  return { downloadMicromamba: true, micromambaBinPath: PATHS.micromambaBin }
}

const inferOptions = (inputs: Inputs): Options => {
  const createEnvironment = inputs.environmentName !== undefined || inputs.environmentFile !== undefined

  const logLevel = inputs.logLevel || (core.isDebug() ? 'debug' : 'warning')

  // if micromambaUrl is specified, use that, otherwise use micromambaVersion (or 'latest' if not specified)
  const micromambaSource = inputs.micromambaUrl
    ? right(inputs.micromambaUrl)
    : left(inputs.micromambaVersion || 'latest')

  // we write to condarc if a condarc file is not already specified
  const writeToCondarc = inputs.condarcFile === undefined

  // defaults to ['bash']
  // if 'none' in list -> []
  const initShell: ShellType[] = !inputs.initShell
    ? ['bash']
    : inputs.initShell.includes('none')
      ? []
      : (inputs.initShell as ShellType[])

  const { downloadMicromamba, micromambaBinPath } = determineMicromambaInstallation(
    inputs.micromambaBinPath,
    inputs.downloadMicromamba
  )

  if (downloadMicromamba) {
    core.info(`Will download micromamba to ${micromambaBinPath}`)
  } else {
    core.info(`Will use pre-installed micromamba at ${micromambaBinPath}`)
  }

  const tempDirectory = getTempDirectory()

  return {
    ...inputs,
    writeToCondarc,
    createEnvironment,
    createArgs: inputs.createArgs || [],
    logLevel,
    micromambaSource,
    downloadMicromamba,
    initShell,
    generateRunShell: inputs.generateRunShell !== undefined ? inputs.generateRunShell : createEnvironment,
    cacheEnvironmentKey:
      inputs.cacheEnvironmentKey || (inputs.cacheEnvironment ? `micromamba-environment-` : undefined),
    cacheDownloadsKey: inputs.cacheDownloadsKey || (inputs.cacheDownloads ? `micromamba-downloads-` : undefined),
    postCleanup: inputs.postCleanup || 'shell-init',
    // use a different path than ~/.condarc to avoid messing up the user's condarc
    condarcFile: inputs.condarcFile
      ? path.resolve(untildify(inputs.condarcFile))
      : path.join(tempDirectory, '.condarc'), // next to the micromamba binary -> easier cleanup
    micromambaBinPath,
    micromambaRunShellPath: path.join(tempDirectory, 'micromamba-shell'),
    micromambaRootPath: inputs.micromambaRootPath
      ? path.resolve(untildify(inputs.micromambaRootPath))
      : PATHS.micromambaRoot
  }
}

const validateInputs = (inputs: Inputs): void => {
  const createEnvironment = inputs.environmentName !== undefined || inputs.environmentFile !== undefined
  if (inputs.micromambaUrl && inputs.micromambaVersion) {
    throw new Error('You must specify either a micromamba URL or a micromamba version, not both.')
  }
  if (inputs.downloadMicromamba === false && (inputs.micromambaUrl || inputs.micromambaVersion)) {
    throw new Error('You cannot specify micromamba-url or micromamba-version when download-micromamba is false.')
  }
  if (inputs.generateRunShell && !createEnvironment) {
    throw new Error("You must create an environment to use 'generate-run-shell'.")
  }
  if (inputs.postCleanup === 'environment' && !createEnvironment) {
    throw new Error("You must create an environment to use post-cleanup: 'environment'.")
  }
  if (inputs.condarcFile && inputs.condarc) {
    throw new Error('You must specify either a condarc file or a condarc string, not both.')
  }
  if ((inputs.cacheEnvironment || inputs.cacheEnvironmentKey) && !createEnvironment) {
    throw new Error("You must create an environment to use 'cache-environment'.")
  }
  if (inputs.cacheEnvironment === false && inputs.cacheEnvironmentKey) {
    throw new Error("You must enable 'cache-environment' to use 'cache-environment-key'.")
  }
  if (inputs.cacheDownloads === false && inputs.cacheDownloadsKey) {
    throw new Error("You must enable 'cache-downloads' to use 'cache-downloads-key'.")
  }
  if (inputs.initShell?.includes('none') && inputs.initShell.length !== 1) {
    throw new Error("You cannot specify 'none' with other shells.")
  }
  if (!inputs.environmentName && !inputs.environmentFile && inputs.createArgs?.length) {
    throw new Error('You need to specify an environment name.')
  }
}

const assertOptions = (options: Options) => {
  const assert = (condition: boolean, message?: string) => {
    if (!condition) {
      throw new Error(message)
    }
  }
  // generate-run-shell => create-env
  assert(!options.generateRunShell || options.createEnvironment)
  // create-env => env-file or env-name specified
  assert(!options.createEnvironment || options.environmentFile !== undefined || options.environmentName !== undefined)
}

export const getRootPrefixFlagForInit = (options: Options) => {
  // latest is always > 1.4.5-0
  if (options.micromambaSource._tag === 'Left' && options.micromambaSource.left < '1.4.5-0') {
    return '-p'
  }
  return '-r'
}

const checkForKnownIssues = (options: Options) => {
  // micromamba 1.4.5 now uses -r for shell init instead of -p
  // https://github.com/mamba-org/mamba/pull/2538
  if (options.initShell && getRootPrefixFlagForInit(options) === '-p') {
    core.warning(
      'You are using a micromamba version < 1.4.5-0 and initialize the shell. This is behavior is deprecated. Please update the micromamba version. For further informations, see https://github.com/mamba-org/setup-micromamba/pull/107'
    )
  }
  const condarcBasename = path.basename(options.condarcFile)
  // https://github.com/mamba-org/mamba/blob/c54c4b530e6638c8712f6246200d0f5a32410b46/libmamba/src/api/configuration.cpp#L955
  const hasValidCondarcName =
    condarcBasename === '.condarc' ||
    condarcBasename === 'condarc' ||
    condarcBasename === '.mambarc' ||
    condarcBasename === 'mambarc' ||
    condarcBasename.endsWith('.yml') ||
    condarcBasename.endsWith('.yaml')
  if (!hasValidCondarcName) {
    core.warning(
      `You are using a condarc file that is not named '.condarc'. This is currently not supported by micromamba, see https://github.com/mamba-org/mamba/issues/1394`
    )
  }
}

const getOptions = () => {
  const inputs: Inputs = {
    condarcFile: parseOrUndefined('condarc-file', z.string()),
    condarc: parseOrUndefined('condarc', z.string()),
    environmentFile: parseOrUndefined('environment-file', z.string()),
    environmentName: parseOrUndefined('environment-name', z.string()),
    createArgs: parseOrUndefinedList('create-args', z.string()),
    logLevel: parseOrUndefined(
      'log-level',
      logLevelSchema,
      'log-level must be either one of `off`, `critical`, `error`, `warning`, `info`, `debug`, `trace`.'
    ),
    micromambaVersion: parseOrUndefined(
      'micromamba-version',
      z.union([z.literal('latest'), z.string().regex(/^\d+\.\d+\.\d+-\d+$/)]),
      'micromamba-version must be either `latest` or a version matching `1.2.3-0`.'
    ),
    micromambaUrl: parseOrUndefined('micromamba-url', z.string().url()),
    downloadMicromamba: parseOrUndefinedJSON('download-micromamba', z.boolean()),
    initShell: parseOrUndefinedList('init-shell', shellSchema),
    generateRunShell: parseOrUndefinedJSON('generate-run-shell', z.boolean()),
    cacheDownloads: parseOrUndefinedJSON('cache-downloads', z.boolean()),
    cacheDownloadsKey: parseOrUndefined('cache-downloads-key', z.string()),
    cacheEnvironment: parseOrUndefinedJSON('cache-environment', z.boolean()),
    cacheEnvironmentKey: parseOrUndefined('cache-environment-key', z.string()),
    postCleanup: parseOrUndefined('post-cleanup', postCleanupSchema),
    micromambaRootPath: parseOrUndefined('micromamba-root-path', z.string()),
    micromambaBinPath: parseOrUndefined('micromamba-binary-path', z.string())
  }
  core.debug(`Inputs: ${JSON.stringify(inputs)}`)
  validateInputs(inputs)
  const options = inferOptions(inputs)
  core.debug(`Inferred options: ${JSON.stringify(options)}`)
  checkForKnownIssues(options)
  assertOptions(options)
  return options
}

let _options: Options
try {
  _options = getOptions()
} catch (error) {
  if (core.isDebug()) {
    throw error
  }
  if (error instanceof Error) {
    core.setFailed(error.message)
    exit(1)
  } else if (typeof error === 'string') {
    core.setFailed(error)
    exit(1)
  }
  throw error
}

export const options = _options
