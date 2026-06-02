import * as os from 'os'
import * as coreDefault from '@actions/core'
import { coreMocked } from './mocking'

const core = process.env.MOCKING ? coreMocked : coreDefault

const MICROMAMBA_RELEASES_API = 'https://api.github.com/repos/mamba-org/micromamba-releases/releases'
const MICROMAMBA_RELEASES_DOWNLOAD = 'https://github.com/mamba-org/micromamba-releases/releases/download'
const MICROMAMBA_RELEASES_LATEST = 'https://github.com/mamba-org/micromamba-releases/releases/latest/download'
const ANACONDA_MICROMAMBA_RELEASE_API = 'https://api.anaconda.org/release/conda-forge/micromamba'

export type ResolvedMicromambaDownload =
  | { source: 'direct'; url: string }
  | { source: 'conda-package'; packageUrl: string; binaryMember: string }

type AnacondaDistribution = {
  version: string
  basename: string
  download_url: string
  labels?: string[]
  attrs: {
    subdir: string
    build_number: number
    labels?: string[]
  }
}

const PRERELEASE_IN_VERSION = /(?:^|[.])(?:rc|alpha|beta|dev)\d/i
const PRERELEASE_WITHOUT_DOT = /\d(?:rc|alpha|beta|dev)\d/i

export const isMicromambaPrereleaseVersion = (version: string): boolean => {
  const versionPart = version.replace(/-\d+$/, '')
  return PRERELEASE_IN_VERSION.test(versionPart) || PRERELEASE_WITHOUT_DOT.test(versionPart)
}

export const parseMicromambaVersionInput = (
  input: string
): { type: 'latest' } | { type: 'version'; condaVersion: string; githubTag: string } => {
  if (input === 'latest') {
    return { type: 'latest' }
  }

  const buildMatch = input.match(/^(.+)-(\d+)$/)
  if (buildMatch) {
    return { type: 'version', condaVersion: buildMatch[1], githubTag: input }
  }

  return { type: 'version', condaVersion: input, githubTag: `${input}-0` }
}

export const isValidMicromambaVersionInput = (input: string): boolean => {
  if (input === 'latest') {
    return true
  }
  if (/^\d+\.\d+\.\d+-\d+$/.test(input)) {
    return true
  }
  if (!/^\d+\.\d+\.\d+/.test(input)) {
    return false
  }
  return isMicromambaPrereleaseVersion(input)
}

const githubAssetUrls = (arch: string, tag: string): string[] => {
  const base = `${MICROMAMBA_RELEASES_DOWNLOAD}/${tag}/micromamba-${arch}`
  if (os.platform() === 'win32') {
    return [`${base}.exe`, base]
  }
  return [base]
}

const githubApiHeaders = (): Record<string, string> => {
  const headers: Record<string, string> = { Accept: 'application/vnd.github+json' }
  const token = process.env.GITHUB_TOKEN
  if (token) {
    headers.Authorization = `Bearer ${token}`
  }
  return headers
}

const fetchJson = async <T>(url: string): Promise<T> => {
  const response = await fetch(url, { headers: githubApiHeaders() })
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} while fetching ${url}`)
  }
  return (await response.json()) as T
}

export const fetchLatestStableMicromambaTag = async (): Promise<string | undefined> => {
  try {
    const releases = await fetchJson<Array<{ tag_name: string; prerelease: boolean }>>(
      `${MICROMAMBA_RELEASES_API}?per_page=100`
    )
    const latestStable = releases.find((release) => !release.prerelease)
    if (!latestStable) {
      core.debug('Could not find a stable micromamba release in the GitHub API response.')
      return undefined
    }
    return latestStable.tag_name
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    core.debug(`Could not query GitHub releases API (${message}), falling back to /releases/latest/download.`)
    return undefined
  }
}

const urlExists = async (url: string): Promise<boolean> => {
  const response = await fetch(url, { method: 'HEAD', headers: githubApiHeaders() })
  return response.ok
}

const resolveGithubAssetUrl = async (arch: string, tag: string): Promise<string> => {
  for (const url of githubAssetUrls(arch, tag)) {
    if (await urlExists(url)) {
      return url
    }
  }
  throw new Error(`Could not find a micromamba binary for release ${tag} on platform ${arch}.`)
}

const latestStableDownloadUrl = (arch: string) => `${MICROMAMBA_RELEASES_LATEST}/micromamba-${arch}`

const getBinaryMember = (subdir: string): string => {
  if (subdir === 'win-64') {
    return 'Library/bin/micromamba.exe'
  }
  return 'bin/micromamba'
}

const fetchCondaMicromambaPackage = async (
  condaVersion: string,
  subdir: string
): Promise<{ packageUrl: string; binaryMember: string }> => {
  const release = await fetchJson<{ distributions: AnacondaDistribution[] }>(
    `${ANACONDA_MICROMAMBA_RELEASE_API}/${condaVersion}`
  )

  const distributions = release.distributions.filter((d) => d.attrs.subdir === subdir)
  if (distributions.length === 0) {
    throw new Error(`No micromamba package found for version ${condaVersion} on platform ${subdir}.`)
  }

  const maxBuild = Math.max(...distributions.map((d) => d.attrs.build_number))
  const candidates = distributions.filter((d) => d.attrs.build_number === maxBuild)

  const labeled = candidates.find((d) => {
    const labels = d.labels ?? d.attrs.labels ?? []
    return labels.includes('micromamba_prerelease')
  })
  const distribution = labeled ?? candidates[0]

  const packageUrl = distribution.download_url.startsWith('//')
    ? `https:${distribution.download_url}`
    : distribution.download_url

  return { packageUrl, binaryMember: getBinaryMember(subdir) }
}

export const resolveMicromambaDownload = async (
  versionInput: string,
  arch: string
): Promise<ResolvedMicromambaDownload> => {
  const parsed = parseMicromambaVersionInput(versionInput)

  if (parsed.type === 'latest') {
    const tag = await fetchLatestStableMicromambaTag()
    if (tag) {
      return { source: 'direct', url: await resolveGithubAssetUrl(arch, tag) }
    }
    return { source: 'direct', url: latestStableDownloadUrl(arch) }
  }

  const { condaVersion, githubTag } = parsed

  if (!isMicromambaPrereleaseVersion(condaVersion)) {
    return { source: 'direct', url: await resolveGithubAssetUrl(arch, githubTag) }
  }

  for (const githubUrl of githubAssetUrls(arch, githubTag)) {
    if (await urlExists(githubUrl)) {
      return { source: 'direct', url: githubUrl }
    }
  }

  const condaPackage = await fetchCondaMicromambaPackage(condaVersion, arch)
  return { source: 'conda-package', ...condaPackage }
}
