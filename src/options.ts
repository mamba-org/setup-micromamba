import * as path from 'path'
import * as os from 'os'
import * as coreDefault from '@actions/core'
import * as z from 'zod'
import { left, right } from 'fp-ts/lib/Either'
import type { Either } from 'fp-ts/lib/Either'
import untildify from 'untildify'
import { coreMocked } from './mocking'

const core = process.env.MOCKING ? coreMocked : coreDefault

export const PATHS = {
  micromambaBin: path.join(os.homedir(), 'micromamba-bin', `micromamba${os.platform() === 'win32' ? '.exe' : ''}`),
  micromambaRoot: path.join(os.homedir(), 'micromamba'),
  // use a different path than ~/.condarc to avoid messing up the user's condarc
  condarc: path.join(os.homedir(), 'micromamba', '.condarc'),
  micromambaRunShell: '/usr/local/bin/micromamba-shell',
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
  initShell: ShellType[]
  generateRunShell: boolean
  cacheDownloadsKey?: string // undefined if cacheDownloads is false
  cacheEnvironmentKey?: string // undefined if cacheEnvironment is false
  postCleanup: PostCleanupType
  micromambaRootPath: string
  micromambaBinPath: string
}>

const postCleanupSchema = z.enum(['none', 'shell-init', 'environment', 'all'])
export type PostCleanupType = z.infer<typeof postCleanupSchema>

const logLevelSchema = z.enum(['off', 'critical', 'error', 'warning', 'info', 'debug', 'trace'])
export type LogLevelType = z.infer<typeof logLevelSchema>

const shellSchema = z.enum(['none', 'bash', 'cmd.exe', 'fish', 'powershell', 'tcsh', 'xonsh', 'zsh'])
type ShellTypeWithNone = z.infer<typeof shellSchema>
export type ShellType = Exclude<ShellTypeWithNone, 'none'>

export type MicromambaSourceType = Either<string, string> // Either<version, url>

const parseOrUndefined = <T>(key: string, schema: z.ZodSchema<T>): T | undefined => {
  const input = core.getInput(key)
  // GitHub actions sets empty inputs to the empty string, but we want undefined
  if (input === '') {
    return undefined
  }
  return schema.parse(input)
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
  return input.split(' ').map((s) => schema.parse(s))
}

const inferOptions = (inputs: Inputs): Options => {
  const createEnvironment = inputs.environmentName !== undefined || inputs.environmentFile !== undefined

  const logLevel = inputs.logLevel || (core.isDebug() ? 'debug' : 'info')

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

  return {
    ...inputs,
    writeToCondarc,
    condarcFile: inputs.condarcFile || PATHS.condarc,
    createEnvironment,
    createArgs: inputs.createArgs || [],
    logLevel,
    micromambaSource,
    initShell,
    generateRunShell: inputs.generateRunShell !== undefined ? inputs.generateRunShell : createEnvironment,
    cacheEnvironmentKey:
      inputs.cacheEnvironmentKey || (inputs.cacheEnvironment ? `micromamba-environment-` : undefined),
    cacheDownloadsKey: inputs.cacheDownloadsKey || (inputs.cacheDownloads ? `micromamba-downloads-` : undefined),
    postCleanup: inputs.postCleanup || 'shell-init',
    micromambaRootPath: inputs.micromambaRootPath ? untildify(inputs.micromambaRootPath) : PATHS.micromambaRoot,
    micromambaBinPath: inputs.micromambaBinPath ? untildify(inputs.micromambaBinPath) : PATHS.micromambaBin
  }
}

const validateInputs = (inputs: Inputs): void => {
  const createEnvironment = inputs.environmentName !== undefined || inputs.environmentFile !== undefined
  if (inputs.micromambaUrl && inputs.micromambaVersion) {
    throw new Error('You must specify either a micromamba URL or a micromamba version, not both.')
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

const getOptions = () => {
  const inputs: Inputs = {
    condarcFile: parseOrUndefined('condarc-file', z.string()),
    condarc: parseOrUndefined('condarc', z.string()),
    environmentFile: parseOrUndefined('environment-file', z.string()),
    environmentName: parseOrUndefined('environment-name', z.string()),
    createArgs: parseOrUndefinedList('create-args', z.string()),
    logLevel: parseOrUndefined('log-level', logLevelSchema),
    micromambaVersion: parseOrUndefined(
      'micromamba-version',
      z.union([z.literal('latest'), z.string().regex(/^\d+\.\d+\.\d+-\d+$/)])
    ),
    micromambaUrl: parseOrUndefined('micromamba-url', z.string().url()),
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
  assertOptions(options)
  return options
}

export const options = getOptions()
