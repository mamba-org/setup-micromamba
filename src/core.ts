import * as coreDefault from '@actions/core'
import { coreMocked } from './mocking'

export const core = process.env.MOCKING || process.env.CLI || !process.env.GITHUB_ACTIONS ? coreMocked : coreDefault
