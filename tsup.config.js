import { defineConfig } from 'tsup'

export default defineConfig({
  entry: {
    index: 'src/main.ts',
    post: 'src/post.ts'
  },
  dts: false,
  clean: true,
  target: 'es2020',
  format: ['cjs'],
  sourcemap: true,
  minify: false,
  // need to bundle dependencies because they aren't available otherwise when run inside the action
  noExternal: [
    '@actions/core',
    '@actions/exec',
    '@actions/cache',
    '@actions/io',
    'node-fetch',
    'untildify',
    'zod',
    'fp-ts',
    // proxy-agent dependencies: https://github.com/TooTallNate/proxy-agents/blob/main/packages/proxy-agent/package.json
    'agent-base',
    'debug',
    'http-proxy-agent',
    'https-proxy-agent',
    'lru-cache',
    'proxy-from-env'
  ]
})
