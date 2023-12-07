let logLevel = 'debug'
export function setLogLevel(level: string) {
  logLevel = level
}

export function logLevelLessEqual(level: string) {
  switch (level) {
    case 'off':
      return false
    case 'critical':
      switch (logLevel) {
        case 'off':
          return false
        default:
          return true
      }
    case 'error':
      switch (logLevel) {
        case 'off':
        case 'critical':
          return false
        default:
          return true
      }
    case 'warning':
      switch (logLevel) {
        case 'off':
        case 'critical':
        case 'error':
          return false
        default:
          return true
      }
    case 'info':
      switch (logLevel) {
        case 'off':
        case 'critical':
        case 'error':
        case 'warning':
          return false
        default:
          return true
      }
    case 'debug':
      switch (logLevel) {
        case 'off':
        case 'critical':
        case 'error':
        case 'warning':
        case 'info':
          return false
        default:
          return true
      }
    case 'trace':
      return true
    default:
      throw new Error(`Unsupported log level ${level}`)
  }
}

export const coreMocked = {
  setFailed: (msg: string) => {
    coreMocked.error(msg)
    process.exit(1)
  },
  getInput: (name: string) => {
    const optionFlag = `--${name}`
    const cliFlagIndex = process.argv.indexOf(optionFlag)
    if (cliFlagIndex > -1) {
      const value = process.argv[cliFlagIndex + 1]
      if (typeof value === 'string') {
        return value
      }
    }
    let value = process.env[`INPUT_${name.replace(/-/g, '_').toUpperCase()}`]
    if (value === undefined) {
      value = process.env[`${name.replace(/-/g, '_').toUpperCase()}`]
      if (value === undefined) {
        if (process.env.MOCKING) {
          throw new Error(`Input required and not supplied: ${name}`)
        }
        return ''
      }
    }
    return value
  },
  // github internally just calls toString on everything, this can lead to confusion, therefore just accepting strings here outright
  setOutput(name: string, value: string) {
    // this is the deprecated format for saving outputs in actions using commands only
    // just using it here to have some sort of consistent output format
    console.log(`::set-output name=${name}::${value}`)
  },
  info: (msg: string) => logLevelLessEqual('info') && console.log(`\u001B[44m\u001B[37m I \u001B[39m\u001B[49m ` + msg), // blue "I"
  debug: (msg: string) =>
    logLevelLessEqual('debug') && console.log(`\u001B[45m\u001B[37m D \u001B[39m\u001B[49m ` + msg), // magenta "D"
  warning: (msg: string) =>
    logLevelLessEqual('warning') && console.warn(`\u001B[43m\u001B[37m W \u001B[39m\u001B[49m ` + msg), // yellow "W"
  notice: (msg: string) =>
    logLevelLessEqual('info') && console.info(`\u001B[44m\u001B[37m ? \u001B[39m\u001B[49m ` + msg), // blue "?"
  error: (msg: string) =>
    logLevelLessEqual('error') && console.error(`\u001B[41m\u001B[37m E \u001B[39m\u001B[49m ` + msg), // red "E"
  startGroup: (label: string) => console.group(`\u001B[47m\u001B[30m ▼ \u001B[39m\u001B[49m ` + label), // white "▼"
  endGroup: () => console.groupEnd(),
  isDebug: () => true,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  saveState: (name: string, value: any) => {
    // TODO: persist the state somewhere
    console.log(`::save-state name=${name}::${value}`)
  },
  getState: (name: string) => {
    return process.env[`STATE_${name.replace(/-/g, '_').toUpperCase()}`] || ''
  },
  addPath: (path: string) => {
    console.log(`::add-path::${path}`)
  },
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  exportVariable: (path: string, value: any) => {
    console.log(`::set-env name=${path}::${value}`)
  }
}
