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
