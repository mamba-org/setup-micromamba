import path from 'path'
import * as fs from 'fs/promises'
import * as cache from '@actions/cache'
import * as coreDefault from '@actions/core'
import { coreMocked } from './mocking'
import { options } from './options'
import { getCondaArch, sha256, sha256Short } from './util'

const core = process.env.MOCKING ? coreMocked : coreDefault

const saveCache = (cachePath: string, cacheKey: string) => {
  core.debug(`Saving cache with key \`${cacheKey}\` ...`)
  core.debug(`Cache path: ${cachePath}`)
  return cache
    .saveCache([cachePath], cacheKey, undefined, false)
    .then((cacheId) => {
      core.info(`Saved cache with ID \`${cacheId}\``)
    })
    .catch((err) => {
      core.error(`Error saving cache: ${err.message}`)
    })
}

const restoreCache = (cachePath: string, cacheKey: string) => {
  core.debug(`Restoring cache with key \`${cacheKey}\` ...`)
  core.debug(`Cache path: ${cachePath}`)
  return cache.restoreCache([cachePath], cacheKey, undefined, undefined, false).then((key) => {
    if (key) {
      core.info(`Restored cache with key \`${key}\``)
    } else {
      core.info(`Cache miss`)
    }
    return key
  })
}

const generateEnvironmentKey = (prefix: string) => {
  const arch = `-${getCondaArch()}`
  const envName = options.environmentName ? `-${options.environmentName}` : ''
  const createArgs = options.createArgs ? `-args-${sha256Short(JSON.stringify(options.createArgs))}` : ''
  const key = `${prefix}${arch}${envName}${createArgs}`
  if (options.environmentFile) {
    return fs.readFile(options.environmentFile, 'utf-8').then((content) => {
      const keyWithFileSha = `${key}-file-${sha256(content)}`
      core.debug(`Generated key \`${keyWithFileSha}\`.`)
      return keyWithFileSha
    })
  }
  core.debug(`Generated key \`${key}\`.`)
  return Promise.resolve(key)
}

const generateDownloadsKey = (prefix: string) => {
  return `${prefix}-${getCondaArch()}`
}

export const saveCacheEnvironment = (environmentName: string) => {
  if (!options.cacheEnvironmentKey) {
    return Promise.resolve()
  }
  const cachePath = path.join(options.micromambaRootPath, 'envs', environmentName)
  core.startGroup(`Caching environment \`${environmentName}\` in \`${cachePath}\` ...`)
  return generateEnvironmentKey(options.cacheEnvironmentKey)
    .then((key) => saveCache(cachePath, key))
    .finally(core.endGroup)
}

/**
 * Restores environment cache
 *
 * @param environmentName the name of the environment to restore
 * @returns string returns the key for the cache hit, otherwise returns undefined
 */
export const restoreCacheEnvironment = (environmentName: string) => {
  if (!options.cacheEnvironmentKey) {
    return Promise.resolve(undefined)
  }
  const cachePath = path.join(options.micromambaRootPath, 'envs', environmentName)
  core.startGroup(`Restoring environment \`${environmentName}\` from \`${cachePath}\` ...`)
  return generateEnvironmentKey(options.cacheEnvironmentKey)
    .then((key) => restoreCache(cachePath, key))
    .finally(core.endGroup)
}

// Inspired by https://github.com/conda-incubator/setup-miniconda/blob/7e642bb2e4ca56ff706818a0febf72bb226d348d/src/delete.ts#L13 (MIT license)
const trimPkgsCacheFolder = (cacheFolder: string) => {
  core.startGroup('Removing uncompressed packages to trim down cache folder...')
  // delete all folders in pkgs that are not the cache folder (i.e., all uncompressed packages)
  return fs
    .readdir(cacheFolder)
    .then((files) => {
      core.debug(`Files in \`${cacheFolder}\`: ${JSON.stringify(files)}`)
      return Promise.all(
        files
          .filter((f) => f !== 'cache') // skip index cache
          .map((f) => path.join(cacheFolder, f))
          .map((f) => fs.lstat(f).then((stat) => ({ path: f, stat })))
      )
    })
    .then((files) => files.filter((f) => f.stat.isDirectory()))
    .then((dirs) => {
      core.debug(`Directories in \`${cacheFolder}\`: ${JSON.stringify(dirs.map((d) => path.basename(d.path)))}`)
      return Promise.all(
        dirs.map((d) => {
          core.info(`Removing \`${path.basename(d.path)}\``)
          return fs.rm(d.path, { recursive: true, force: true })
        })
      )
    })
    .finally(() => core.endGroup())
}

export const saveCacheDownloads = () => {
  core.debug(`Cache downloads key: ${options.cacheDownloadsKey}`)
  if (!options.cacheDownloadsKey) {
    return Promise.resolve()
  }
  const cachePath = path.join(options.micromambaRootPath, 'pkgs')
  const cacheDownloadsKey = generateDownloadsKey(options.cacheDownloadsKey)
  return trimPkgsCacheFolder(cachePath)
    .then(() => {
      core.startGroup(`Saving cache for \`${cachePath}\` ...`)
      return saveCache(cachePath, cacheDownloadsKey)
    })
    .finally(core.endGroup)
}

/**
 * Restores package downloads cache
 *
 * @returns string returns the key for the cache hit, otherwise returns undefined
 */
export const restoreCacheDownloads = () => {
  core.debug(`Cache downloads key: ${options.cacheDownloadsKey}`)
  if (!options.cacheDownloadsKey) {
    return Promise.resolve(undefined)
  }
  const cachePath = path.join(options.micromambaRootPath, 'pkgs')
  const cacheDownloadsKey = generateDownloadsKey(options.cacheDownloadsKey)
  core.startGroup(`Restoring downloads from \`${cachePath}\` ...`)
  return restoreCache(cachePath, cacheDownloadsKey).finally(core.endGroup)
}
