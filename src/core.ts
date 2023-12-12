import * as coreDefault from '@actions/core'
import { coreMocked } from './mocking'

export const core = process.env.MOCKING || process.env.CLI || process.env.INIT_CWD || !process.env.GITHUB_ACTIONS ? coreMocked : coreDefault
