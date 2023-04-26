# setup-micromamba

---

[![CI](https://github.com/mamba-org/setup-micromamba/actions/workflows/test.yml/badge.svg)](https://github.com/mamba-org/setup-micromamba/actions/workflows/test.yml)

GitHub Action to set up the [micromamba](https://github.com/mamba-org/mamba#micromamba) package manager.

## Usage

```yml
- uses: mamba-org/setup-micromamba@v1
  with:
    micromamba-version: '1.3.1-0'
    environment-file: environment.yml
    init-shell: '["bash", "powershell"]'
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

### Shell initialization

In order to be able to activate micromamba environments, you need to initialize your shell.
`setup-micromamba` can create shell initialization scripts for different shells (by calling `micromamba shell init -s <shell-name>`).
By default, it will create shell initialization scripts for `bash`.
If you want to customize this, you can use the `init-shell` input.

```yml
- uses: mamba-org/setup-micromamba@v1
  with:
    init-shell: '["bash", "powershell", "cmd.exe"]'
```

Please read [about login shells](#about-login-shells) for more information about the shell initialization.

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
    create-args: |
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
    create-args: |
      -v
```

### Custom shell

`setup-micromamba` will allow you to run commands in the created micromamba environment with a custom shell wrapper. In this &#8220;shell&#8221;, the micromamba is activated and the commands are executed.
With this, you don't need to initialize your shell and activate the environment which may come in handy for self-hosted runners that persist between jobs.

> Under the hood, this shell wrapper runs `micromamba run -r <root-prefix-path> -n <env-name> <command>` with `<command>` being a file containing the part that you specify in the `run:` section of your workflow. 
> See [ADR 0277](https://github.com/actions/runner/blob/main/docs/adrs/0277-run-action-shell-options.md) for more information about how the `shell:` input works in GitHub Actions.

```yml
- uses: mamba-org/setup-micromamba@v1
  with:
    environment-file: environment.yml
- run: |
    pytest --version
    pytest
  shell: micromamba-shell {0}
```

### Custom .condarc file

To specify custom channels or other micromamba settings, you may want to use `.condarc` files to do this.

`setup-micromamba` allows you to specify a custom `.condarc` file using either the `condarc-file` or the `condarc` input.

When you specify `condarc-file`, `setup-micromamba` will use this file for all micromamba commands.

When you specify `condarc`, `setup-micromamba` will create a `.condarc` in the root prefix of the micromamba installation (to not mess with the `~/.condarc` that may be overwritten on self-hosted runners) and use this file for all micromamba commands.

If nothing is specified, `setup-micromamba` will create a `.condarc` in the root prefix of the micromamba installation with `conda-forge` as the only channel.

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

### Debugging

TODO screenshot of rerun with debug

### Post action cleanup

TODO for custom runners

## Notes on caching

TODO

## More examples

Reference tests

## About login shells...

TODO

## Development

TODO
explain test.sh
act
