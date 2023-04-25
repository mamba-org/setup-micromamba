import path from 'path'
import * as fs from 'fs/promises'
import * as cache from '@actions/cache'
import * as coreDefault from '@actions/core'
import { coreMocked } from './mocking'
import { options } from './options'
import { sha256, sha256Short } from './util'

const core = process.env.MOCKING ? coreMocked : coreDefault

const saveCache = (cachePath: string, cacheKey: string) => {
  cache
    .saveCache([cachePath], cacheKey, undefined, false)
    .then((cacheId) => {
      core.info(`Saved cache with ID \`${cacheId}\``)
    })
    .catch((err) => {
      core.error(`Error saving cache: ${err.message}`)
    })
}

const restoreCache = (cachePath: string, cacheKey: string) => {
  return cache.restoreCache([cachePath], cacheKey, undefined, undefined, false).then((key) => {
    if (key) {
      core.info(`Restored cache with key \`${key}\``)
    } else {
      core.info(`Cache miss`)
    }
    return key
  })
}

const generateKey = (prefix: string) => {
  const envName = options.environmentName ? `-${options.environmentName}` : ''
  const createArgs = options.createArgs ? `-args-${sha256Short(JSON.stringify(options.createArgs))}` : ''
  if (options.environmentFile) {
    return fs
      .readFile(options.environmentFile, 'utf-8')
      .then((content) => `${prefix}${envName}${createArgs}-file-${sha256(content)}`)
  }
  return Promise.resolve(`${prefix}${envName}${createArgs}`)
}

export const saveCacheEnvironment = (environmentName: string) => {
  if (!options.cacheEnvironmentKey) {
    return Promise.resolve()
  }
  const cachePath = path.join(options.micromambaRootPath, 'envs', environmentName)
  core.info(`Caching environment \`${environmentName}\` in \`${cachePath}\` ...`)
  return generateKey(options.cacheEnvironmentKey).then((key) => saveCache(cachePath, key))
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
  core.info(`Restoring environment \`${environmentName}\` from \`${cachePath}\` ...`)
  return restoreCache(cachePath, options.cacheEnvironmentKey)
}

// Inspired by https://github.com/conda-incubator/setup-miniconda/blob/7e642bb2e4ca56ff706818a0febf72bb226d348d/src/delete.ts#L13 (MIT license)
const trimPkgsCacheFolder = (cacheFolder: string) => {
  core.startGroup('Removing uncompressed packages to trim down cache folder...')
  // delete all folders in pkgs that are not the cache folder
  return fs
    .readdir(cacheFolder)
    .then((files) =>
      Promise.all(
        files
          .filter((f) => f !== 'cache') // skip index cache
          .map((f) => path.join(cacheFolder, f))
          .map((f) => fs.lstat(f).then((stat) => ({ path: f, stat })))
      )
    )
    .then((files) => files.filter((f) => f.stat.isDirectory()))
    .then((dirs) => Promise.all(dirs.map((d) => fs.rm(d.path, { recursive: true, force: true }))))
    .finally(() => core.endGroup())
}

export const saveCacheDownloads = () => {
  if (!options.cacheDownloadsKey) {
    return Promise.resolve()
  }
  const cachePath = path.join(options.micromambaRootPath, 'pkgs')
  core.info(`Caching downloads in \`${cachePath}\` ...`)
  // if we don't put this into a variable, typescript complains
  const cacheDownloadsKey = options.cacheDownloadsKey
  return trimPkgsCacheFolder(cachePath).then(() => saveCache(cachePath, cacheDownloadsKey))
}

/**
 * Restores package downloads cache
 *
 * @returns string returns the key for the cache hit, otherwise returns undefined
 */
export const restoreCacheDownloads = () => {
  if (!options.cacheDownloadsKey) {
    return Promise.resolve(undefined)
  }
  const cachePath = path.join(options.micromambaRootPath, 'pkgs')
  return restoreCache(cachePath, options.cacheDownloadsKey)
}
