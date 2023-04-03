import * as z from 'zod'

const micromambaUrlSchema = z.union([z.literal(''), z.string().url()])

const micromambaVersionSchema = z.union([z.literal(''), z.string().regex(/^\d+\.\d+\.\d+$/)])

// TODO: only use valid log levels
const logLevelSchema = z.enum(['trace', 'debug', 'info', 'warn', 'error', 'critical', 'off'])

const extraSpecsSchema = z.array(z.string())

const createArgsSchema = z.array(z.string())

const createEnvSchema = z.boolean()

const initMicromambaSchema = z.array(z.enum(['bash', 'zsh', 'xonsh', 'powershell', 'cmd']))

export {
  micromambaUrlSchema,
  micromambaVersionSchema,
  logLevelSchema,
  extraSpecsSchema,
  createArgsSchema,
  createEnvSchema,
  initMicromambaSchema
}
