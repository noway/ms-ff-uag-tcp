# Enviorment
Using `pyenv` and `virtualenv`:

```bash
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"

pyenv install 3.5.2
virtualenv -p python3 venv

pyenv shell 3.5.2
. ./venv/bin/activate

pip install -r requirements.txt
```

# Config
```bash
$ cp -a config-example/ config/
$ vi config/creds.txt
```

# Init
For a first start invocation with `--init` is required, i.e.

```bash
./ms-ff-uag-tcp --init --quiet 1
```

