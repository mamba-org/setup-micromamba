import * as coreDefault from '@actions/core'
import * as z from 'zod'
import { coreMocked } from './mocking'

const core = process.env.MOCKING ? coreMocked : coreDefault

type Inputs = {
  condarcFile?: string
  condarc?: string
  createEnvironment?: boolean // TODO: is this needed?
  environmentFile?: string
  environmentName?: string
  extraSpecs?: string[]
  createArgs?: string
  logLevel?: LogLevelType
  micromambaVersion?: string
  micromambaUrl?: string
  initShell?: ShellType[]
  generateRunShell?: boolean
  cacheDownloads?: boolean
  cacheDownloadsKey?: string
  cacheEnvironment?: boolean
  cacheEnvironmentKey?: string
  postCleanup?: PostCleanupType
}

export type Options = {
  condarcFile?: string
  condarc?: string
  createEnvironment: boolean
  environmentFile?: string
  environmentName?: string
  extraSpecs: string[]
  createArgs?: string // TODO: is this needed?
  logLevel: LogLevelType
  micromambaVersion: string
  micromambaUrl?: string
  initShell: ShellType[]
  generateRunShell: boolean
  cacheDownloads: boolean
  cacheDownloadsKey?: string
  cacheEnvironment: boolean
  cacheEnvironmentKey?: string
  postCleanup: PostCleanupType
}

const postCleanupSchema = z.enum(['none', 'shell-init', 'environment', 'all'])
export type PostCleanupType = z.infer<typeof postCleanupSchema>

const logLevelSchema = z.enum(['off', 'critical', 'error', 'warning', 'info', 'debug', 'trace'])
export type LogLevelType = z.infer<typeof logLevelSchema>

const shellSchema = z.enum(['bash', 'cmd.exe', 'fish', 'powershell', 'tcsh', 'xonsh', 'zsh'])
export type ShellType = z.infer<typeof shellSchema>

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

const inferOptions = (inputs: Inputs): Options => {
  const createEnvironment =
    inputs.createEnvironment || inputs.environmentName !== undefined || inputs.environmentFile !== undefined
  const logLevel = inputs.logLevel || (core.isDebug() ? 'debug' : 'info')
  const options = {
    ...inputs,
    createEnvironment,
    extraSpecs: inputs.extraSpecs || [],
    logLevel,
    micromambaVersion: inputs.micromambaVersion || 'latest', // if micromambaUrl is set, this is ignored
    initShell: inputs.initShell || ['bash'],
    generateRunShell: inputs.generateRunShell !== undefined ? inputs.generateRunShell : createEnvironment,
    cacheDownloads: inputs.cacheDownloads !== undefined ? inputs.cacheDownloads : true,
    cacheEnvironment: inputs.cacheEnvironment !== undefined ? inputs.cacheEnvironment : true,
    postCleanup: inputs.postCleanup || 'shell-init'
  }
  return options
}

const validateInputs = (inputs: Inputs): void => {
  if (inputs.createEnvironment) {
    if (!inputs.environmentFile && !inputs.environmentName) {
      throw new Error('You must specify either an environment file or an environment name to create an environment.')
    }
  }
  if (inputs.generateRunShell && !(inputs.createEnvironment === false)) {
    throw new Error('You must not create an environment to use generate-run-shell.')
  }
  if (
    inputs.postCleanup === 'environment' &&
    !inputs.createEnvironment &&
    inputs.environmentName === undefined &&
    inputs.environmentFile === undefined
  ) {
    throw new Error("You must create an environment to use post-cleanup: 'environment'.")
  }
  if (inputs.condarcFile && inputs.condarc) {
    throw new Error('You must specify either a condarc file or a condarc string, not both.')
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

export const getOptions = () => {
  const inputs: Inputs = {
    condarcFile: parseOrUndefined('condarc-file', z.string()),
    condarc: parseOrUndefined('condarc', z.string()),
    environmentFile: parseOrUndefined('environment-file', z.string()),
    environmentName: parseOrUndefined('environment-name', z.string()),
    extraSpecs: parseOrUndefinedJSON('extra-specs', z.array(z.string())),
    createArgs: parseOrUndefined('create-args', z.string()),
    createEnvironment: parseOrUndefinedJSON('create-environment', z.boolean()),
    logLevel: parseOrUndefined('log-level', logLevelSchema),
    micromambaVersion: parseOrUndefined(
      'micromamba-version',
      z.union([z.literal('latest'), z.string().regex(/^\d+\.\d+\.\d+-\d+$/)])
    ),
    micromambaUrl: parseOrUndefined('micromamba-url', z.string().url()),
    initShell: parseOrUndefinedJSON('init-shell', z.array(shellSchema)),
    generateRunShell: parseOrUndefinedJSON('generate-run-shell', z.boolean()),
    cacheDownloads: parseOrUndefinedJSON('cache-downloads', z.boolean()),
    cacheDownloadsKey: parseOrUndefined('cache-downloads-key', z.string()),
    cacheEnvironment: parseOrUndefinedJSON('cache-environment', z.boolean()),
    cacheEnvironmentKey: parseOrUndefined('cache-environment-key', z.string()),
    postCleanup: parseOrUndefined('post-cleanup', postCleanupSchema)
  }
  core.debug(`Inputs: ${JSON.stringify(inputs)}`)
  validateInputs(inputs)
  const options = inferOptions(inputs)
  core.debug(`Inferred options: ${JSON.stringify(options)}`)
  assertOptions(options)
  return options
}
