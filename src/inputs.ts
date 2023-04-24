import * as coreDefault from '@actions/core'
import * as z from 'zod'
import { coreMocked } from './mocking'

const core = process.env.MOCKING ? coreMocked : coreDefault

export type Input = {
  condarcFile: string | undefined
  condarc: string | undefined
  environmentFile: string | undefined
  environmentName: string | undefined
  extraSpecs: string[] | undefined
  createArgs: string | undefined
  createEnvironment: boolean | undefined
  logLevel: LogLevelType
  micromambaVersion: string | undefined
  micromambaUrl: string | undefined
  initShell: ShellType[]
  generateRunShell: boolean
  cacheDownloads: boolean | undefined
  cacheDownloadsKey: string | undefined
  cacheEnvironment: boolean | undefined
  cacheEnvironmentKey: string | undefined
  postCleanup: PostCleanupType
}

const postCleanupSchema = z.enum(['none', 'shell-init', 'environment', 'all'])
export type PostCleanupType = z.infer<typeof postCleanupSchema>

const logLevelSchema = z.enum(['off', 'critical', 'error', 'warning', 'info', 'debug', 'trace'])
export type LogLevelType = z.infer<typeof logLevelSchema>

const shellSchema = z.enum(['bash', 'cmd.exe', 'fish', 'powershell', 'tcsh', 'xonsh', 'zsh'])
export type ShellType = z.infer<typeof shellSchema>

const parseOrUndefined = <T>(input: string, schema: z.ZodSchema<T>): T | undefined => {
  // GitHub actions sets empty inputs to the empty string, but we want undefined
  if (input === '') {
    return undefined
  }
  return schema.parse(input)
}

export const parseInputs = (): Input => {
  const inputs = {
    // TODO: parseOrUndefined is not needed everywhere
    condarcFile: parseOrUndefined(core.getInput('condarc-file'), z.string()),
    condarc: parseOrUndefined(core.getInput('condarc'), z.string()),
    environmentFile: parseOrUndefined(core.getInput('environment-file'), z.string()),
    environmentName: parseOrUndefined(core.getInput('environment-name'), z.string()),
    extraSpecs: parseOrUndefined(
      core.getInput('extra-specs') && JSON.parse(core.getInput('extra-specs')),
      z.array(z.string())
    ),
    createArgs: parseOrUndefined(core.getInput('create-args'), z.string()),
    createEnvironment: parseOrUndefined(JSON.parse(core.getInput('create-environment')), z.boolean()),
    logLevel: logLevelSchema.parse(core.getInput('log-level')),
    micromambaVersion: parseOrUndefined(
      core.getInput('micromamba-version'),
      z.union([z.literal('latest'), z.string().regex(/^\d+\.\d+\.\d+-\d+$/)])
    ),
    micromambaUrl: parseOrUndefined(core.getInput('micromamba-url'), z.string().url()),
    // cacheKey: parseOrUndefined(core.getInput('cache-key'), z.string()),
    initShell:
      parseOrUndefined(core.getInput('init-shell') && JSON.parse(core.getInput('init-shell')), z.array(shellSchema)) ||
      [],
    generateRunShell: z.boolean().parse(JSON.parse(core.getInput('generate-run-shell'))),
    cacheDownloads: parseOrUndefined(JSON.parse(core.getInput('cache-downloads')), z.boolean()),
    cacheDownloadsKey: parseOrUndefined(core.getInput('cache-downloads-key'), z.string()),
    cacheEnvironment: parseOrUndefined(JSON.parse(core.getInput('cache-environment')), z.boolean()),
    cacheEnvironmentKey: parseOrUndefined(core.getInput('cache-environment-key'), z.string()),
    postCleanup: parseOrUndefined(core.getInput('post-cleanup'), postCleanupSchema) || 'all'
  }
  return inputs
}

export const validateInputs = (inputs: Input): void => {
  if (inputs.createEnvironment) {
    if (!inputs.environmentFile && (!inputs.environmentName || !inputs.extraSpecs)) {
      throw new Error(
        'You must specify either an environment file or an environment name and extra specs to create an environment.'
      )
    }
  }
  if (inputs.generateRunShell && !inputs.createEnvironment) {
    throw new Error('You must create an environment to use generate-run-shell: true.')
  }
  if (!inputs.createEnvironment && inputs.postCleanup === 'environment') {
    throw new Error("You must create an environment to use post-cleanup: 'environment'.")
  }
  if (inputs.condarcFile && inputs.condarc) {
    throw new Error('You must specify either a condarc file or a condarc string, not both.')
  }
}
