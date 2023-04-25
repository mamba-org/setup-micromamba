# setup-micromamba

---

[![CI](https://github.com/mamba-org/setup-micromamba/actions/workflows/test.yml/badge.svg)](https://github.com/mamba-org/setup-micromamba/actions/workflows/test.yml)

GitHub Action to set up the [micromamba](https://github.com/mamba-org/mamba#micromamba) package manager.

## Usage

```yaml
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

TODO

### Environment creation

environment-file and environment-name
create-args
TODO <and automatic activation>

### Custom shell

TODO

### Custom .condarc file

TODO

### Caching

TODO

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
