import path from 'path'
import fs from 'fs'
import * as io from '@actions/io'
import { core } from './core'
import { options } from './options'
import { getMicromambaUrl, determineEnvironmentName } from './util'
import { logLevelLessEqual } from './mocking'
import {
  downloadMicromamba,
  generateCondarc,
  installEnvironment,
  generateMicromambaRunShell,
  generateInfo
} from './main'

const run = async () => {
  if (process.platform === 'win32') {
    // Work around bug in Mamba: https://github.com/mamba-org/mamba/issues/1779
    // This prevents using setup-micromamba without bash
    core.addPath(path.dirname(await io.which('cygpath', true)))
  }

  let genInfo = false
  if (!fs.existsSync(options.micromambaBinPath)) {
    genInfo = true
    await downloadMicromamba(getMicromambaUrl(options.micromambaSource))
    await generateCondarc()
  }
  if (options.createEnvironment) {
    const environmentName = await determineEnvironmentName(options.environmentName, options.environmentFile)
    const environmentPath = path.join(options.micromambaRootPath, 'envs', environmentName)
    if (!fs.existsSync(environmentPath)) {
      genInfo = true
      await installEnvironment()
      await generateMicromambaRunShell()
    }
  }

  if (genInfo && logLevelLessEqual('info')) {
    await generateInfo()
  }
}

run().catch((error) => {
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
})
