import * as coreDefault from '@actions/core'
import * as z from 'zod'
import { coreMocked } from './mocking'

const core = process.env.MOCKING ? coreMocked : coreDefault

export type Input = {
  micromambaUrl: string | undefined
  micromambaVersion: string | undefined
  logLevel: LogLevelType
  condarcFile: string | undefined
  environmentFile: string | undefined
  environmentName: string | undefined
  extraSpecs: string[] | undefined
  createArgs: string[] | undefined
  createEnvironment: boolean | undefined
  cacheKey: string | undefined
  initMicromamba: string[]
}

const logLevelSchema = z.enum(['off', 'critical', 'error', 'warning', 'info', 'debug', 'trace'])
export type LogLevelType = z.infer<typeof logLevelSchema>

const parseOrUndefined = <T>(input: string, schema: z.ZodSchema<T>): T | undefined => {
  if (input === '') {
    return undefined
  }
  return schema.parse(input)
}

export const parseInputs = (): Input => {
  const inputs = {
    // TODO: parseOrUndefined is not needed everywhere
    micromambaUrl: parseOrUndefined(core.getInput('micromamba-url'), z.string().url()),
    micromambaVersion: parseOrUndefined(
      core.getInput('micromamba-version'),
      z.union([z.literal('latest'), z.string().regex(/^\d+\.\d+\.\d+-\d+$/)])
    ),
    logLevel: logLevelSchema.parse(core.getInput('log-level')),
    condarcFile: parseOrUndefined(core.getInput('condarc-file'), z.string()),
    environmentFile: parseOrUndefined(core.getInput('environment-file'), z.string()),
    environmentName: parseOrUndefined(core.getInput('environment-name'), z.string()),
    extraSpecs: parseOrUndefined(core.getInput('extra-specs'), z.array(z.string())),
    createArgs: parseOrUndefined(core.getInput('create-args'), z.array(z.string())),
    createEnvironment: parseOrUndefined(JSON.parse(core.getInput('create-environment')), z.boolean()),
    cacheKey: parseOrUndefined(core.getInput('cache-key'), z.string()),
    initMicromamba:
      parseOrUndefined(
        core.getInput('init-micromamba') && JSON.parse(core.getInput('init-micromamba')),
        z.array(z.enum(['bash', 'zsh', 'xonsh', 'powershell', 'cmd']))
      ) || []
  }
  return inputs
}
