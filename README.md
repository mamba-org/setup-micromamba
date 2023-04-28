# setup-micromamba

[![CI](https://github.com/mamba-org/setup-micromamba/actions/workflows/test.yml/badge.svg)](https://github.com/mamba-org/setup-micromamba/actions/workflows/test.yml)

GitHub Action to set up the [micromamba](https://github.com/mamba-org/mamba#micromamba) package manager.

## Usage

```yml
- uses: mamba-org/setup-micromamba@v1
  with:
    micromamba-version: '1.3.1-0'
    environment-file: environment.yml
    init-shell: >-
      bash
      powershell
    cache-environment: true
    post-cleanup: 'all'
- name: Import numpy in micromamba environment (bash)
  run: python -c "import numpy"
  shell: bash -el {0}
- name: Import numpy in micromamba environment (pwsh)
  run: python -c "import numpy"
  shell: pwsh
- name: Run custom command in micromamba environment
  run: pytest --version
  shell: micromamba-shell {0}
```

## Features

To see all available input arguments, see the [`action.yml`](action.yml) file.

### Environment creation

`setup-micromamba` allows you to create micromamba environments from an environment file or from a list of packages.
You can use `environment-file`, `environment-specs` and `create-args` arguments to specify the environment creation.
If you don't specify any of these arguments, `setup-micromamba` will skip the environment creation.

After the environment has been created, `setup-micromamba` will write `micromamba activate <env-name>` into the rc file of all shells that are [initialized](#shell-initialization).
This will automatically activate the environment when the shell is started.

#### Create environment from environment file

```yml
- uses: mamba-org/setup-micromamba@v1
  with:
    environment-file: environment.yml
```

#### Create environment from environment specs

You can specify extra environment specs using the `create-args` input.

```yml
- uses: mamba-org/setup-micromamba@v1
  with:
    # the create command looks like this:
    # `micromamba create -n test-env python=3.10 numpy`
    environment-name: test-env
    create-args: >-
      python=3.10
      numpy
```

#### Custom arguments

You can specify custom arguments for the `micromamba create` command using the `create-args` input. See `micromamba create --help` for more information.

> This is the same argument as in the [previous example](#create-environment-from-environment-specs) but with different semantics. 
> This is because internally, `setup-micromamba` uses the `micromamba create` command to create the environment from the environment file and there, extra specs are specified by adding them as extra arguments to the `micromamba create` command.

```yml
- uses: mamba-org/setup-micromamba@v1
  with:
    environment-file: environment.yml
    create-args: -v
```

### Shell initialization

In order to be able to activate micromamba environments, you need to initialize your shell.
`setup-micromamba` can create shell initialization scripts for different shells (by calling `micromamba shell init -s <shell>`).
By default, it will create shell initialization scripts for `bash`.
If you want to customize this, you can use the `init-shell` input.

```yml
- uses: mamba-org/setup-micromamba@v1
  with:
    init-shell: bash
```

In case you don't want to initialize your shell, you can set `init-shell` to `none`.

You can also specify multiple shells by separating them with a space (or using the `>-` YAML block scalar)

```yml
- uses: mamba-org/setup-micromamba@v1
  with:
    init-shell: >-
      bash
      powershell
    # or
    init-shell: bash powershell
```

Please read [about login shells](#about-login-shells) for more information about the shell initialization.

### Custom `micromamba-shell` wrapper

`setup-micromamba` will allow you to run commands in the created micromamba environment with a custom shell wrapper. In this &#8220;shell&#8221;, the micromamba is activated and the commands are executed.
With this, you don't need to initialize your shell and activate the environment which may come in handy for self-hosted runners that persist between jobs.
You can set this behavior by specifying the `generate-run-shell` input (defaults to `true`).

> Under the hood, this shell wrapper runs `micromamba run -r <root-prefix-path> -n <env-name> <command>` with `<command>` being a file containing the part that you specify in the `run:` section of your workflow. 
> See the [official documentation](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#custom-shell) and [ADR 0277](https://github.com/actions/runner/blob/main/docs/adrs/0277-run-action-shell-options.md) for more information about how the `shell:` input works in GitHub Actions.

> ⚠️ Only available on macOS and Linux.

```yml
- uses: mamba-org/setup-micromamba@v1
  with:
    generate-run-shell: true
    environment-file: environment.yml
- run: |
    pytest --version
    pytest
  shell: micromamba-shell {0}
```

### Custom `.condarc` file

To specify custom channels or other micromamba settings, you may want to use `.condarc` files to do this.

`setup-micromamba` allows you to specify a custom `.condarc` file using either the `condarc-file` or the `condarc` input.

When you specify `condarc-file`, `setup-micromamba` will use this file for all micromamba commands.

When you specify `condarc`, `setup-micromamba` will create a `.condarc` next to the micromamba binary (to not mess with the `~/.condarc` that may be overwritten on self-hosted runners) and use this file for all micromamba commands.

If nothing is specified, `setup-micromamba` will create a `.condarc` next to the micromamba binary with `conda-forge` as the only channel.

```yml
- uses: mamba-org/setup-micromamba@v1
  with:
    environment-file: environment.yml
    condarc-file: /path/to/.condarc
```

```yml
- uses: mamba-org/setup-micromamba@v1
  with:
    environment-file: environment.yml
    condarc: |
      channels:
        - my-custom-channel
        - conda-forge
        - pytorch
```

### Caching

If you want to cache your micromamba environment or packages, you can do this by setting the `cache-environment` (or `cache-environment-key`) or `cache-downloads` (or `cache-downloads-key`) inputs.

If `cache-environment` is set to `true` and `cache-environment-key` is not specified, `setup-micromamba` will use the default cache key (`micromamba-environment`). Similar behavior applies to `cache-downloads` and `cache-downloads-key`.

> Note that the specified cache key is only the prefix of the real cache key.
> `setup-micromamba` will append a hash of the environment file and the `custom-args` as well as the environment name and OS to the cache key.

```yml
- uses: mamba-org/setup-micromamba@v1
  with:
    environment-file: environment.yml
    # only cache environment
    cache-environment: true
    cache-downloads: false
```

```yml
- uses: mamba-org/setup-micromamba@v1
  with:
    environment-file: environment.yml
    # persist only for runs on this commit.
    cache-environment-key: environment-${{ github.sha }}
    cache-downloads-key: downloads-${{ github.sha }}
```

```yml
- name: Get current date
  id: date
  run: echo "date=$(date +%Y-%m-%d)" >> "${GITHUB_OUTPUT}"
- uses: mamba-org/setup-micromamba@v1
  with:
    environment-file: environment.yml
    # persist on the same day.
    cache-environment-key: environment-${{ steps.date.outputs.date }}
    cache-downloads-key: downloads-${{ steps.date.outputs.date }}
```

> See [Notes on caching](#notes-on-caching) for more information about caching.

### Debugging

There are two types of debug logging that you can enable.

#### Debug logging of the action

The first one is the debug logging of the action itself.
This can be enabled by running the action with the `ACTIONS_STEP_DEBUG` environment variable set to `true`.

```yml
- uses: mamba-org/setup-micromamba@v1
  env:
    ACTIONS_STEP_DEBUG: true
```

Alternatively, you can enable debug logging for the action by re-running the action in debug mode:

![Re-run in debug mode](.github/assets/enable-debug-logging-light.png#gh-light-mode-only)
![Re-run in debug mode](.github/assets/enable-debug-logging-dark.png#gh-dark-mode-only)

> For more information about debug logging in GitHub Actions, see [the official documentation](https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/enabling-debug-logging).

#### Debug logging of micromamba

The second type is the debug logging of the micromamba executable.
This can be specified by setting the `log-level` input.

```yml
- uses: mamba-org/setup-micromamba@v1
  with:
    environment-file: environment.yml
    # supports off, critical, error, warning, info, debug, trace
    log-level: debug
```

If nothing is specified, `setup-micromamba` will default to `info` or `debug` depending on if [debug logging is enabled for the action](#debug-logging-of-the-action).

### Post action cleanup

On self hosted runners, it may happen that some files are persisted between jobs.
This can lead to problems when the next job is run.
To avoid this, you can use the `post-cleanup` input to specify the post cleanup behavior of the action (i.e., what happens _after_ all your commands have been executed).

There is a total of 4 options:
- `none`: No cleanup is performed.
- `shell-init`: The shell initialization files are removed by executing `micromamba shell deinit -s <shell>`.
- `environment`: Shell initialization files and the installed environment are removed.
- `all`: Shell initialization files as well as the micromamba root folder and the binary are removed.

If nothing is specified, `setup-micromamba` will default to `shell-init`.

```yml
- uses: mamba-org/setup-micromamba@v1
  with:
    environment-file: environment.yml
    post-cleanup: environment
```

## More examples

If you want to see more examples, you can take a look at the [GitHub Workflows of this repository](.github/workflows/).

## Notes on caching

### Branches have separate caches

Due to a [security limitation of GitHub Actions](https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows#restrictions-for-accessing-a-cache)
any caches created on a branch will not be available on the main/parent branch
after merging. This also applies to PRs.

In contrast, branches *can* use a cache created on the main/parent branch. 

See also [this thread](https://github.com/mamba-org/provision-with-micromamba/issues/42#issuecomment-1062007161).

### When to use download caching

Please see [this comment for now](https://github.com/mamba-org/provision-with-micromamba/pull/38#discussion_r808837618).

### When to use environment caching

Please see [this comment for now](https://github.com/mamba-org/provision-with-micromamba/pull/38#discussion_r808837618).

## About login shells...

Some shells require special syntax (e.g. `bash -l {0}`). You can set this up with the `defaults` option:

```yaml
jobs:
  myjob:
    defaults:
      run:
        shell: bash -l {0}

# or top-level:
defaults:
  run:
    shell: bash -l {0}
jobs:
  ...
```

Find the reasons below (taken from [setup-miniconda](https://github.com/conda-incubator/setup-miniconda/blob/master/README.md#important)):

- Bash shells do not use `~/.profile` or `~/.bashrc` so these shells need to be
  explicitly declared as `shell: bash -l {0}` on steps that need to be properly
  activated (or use a default shell). This is because bash shells are executed
  with `bash --noprofile --norc -eo pipefail {0}` thus ignoring updated on bash
  profile files made by `micromamba shell init bash`.
- Cmd shells do not run `Autorun` commands so these shells need to be
  explicitly declared as `shell: cmd /C call {0}` on steps that need to be
  properly activated (or use a default shell). This is because cmd shells are
  executed with `%ComSpec% /D /E:ON /V:OFF /S /C "CALL "{0}""` and the `/D` flag
  disabled execution of `Command Processor/Autorun` Windows registry keys, which
  is what `micromamba shell init cmd.exe` sets.

For further information, see 
[`jobs.<job_id>.steps[*].shell`](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idstepsshell) 
and [this thread](https://github.com/orgs/community/discussions/25061).

## Development

1. Clone this repository.
2. Run `pnpm install` inside the repository (if you don't have [`pnpm`](https://github.com/pnpm/pnpm) installed, you can install it with `npm install -g pnpm` or `brew install pnpm`).
3. Run `pnpm run dev` for live transpilation of the TypeScript source code.
4. To test the action, you can run [`act`](https://github.com/nektos/act) (inside docker) or [`test.sh`](test.sh) (on your local machine).
