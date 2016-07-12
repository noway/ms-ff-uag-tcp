#!/bin/bash
cd "$(dirname "$(readlink -f "$(command -v "$0")")")"

export PYENV_ROOT="$PWD/.pyenv"
curl -L https://raw.githubusercontent.com/yyuu/pyenv-installer/master/bin/pyenv-installer | bash

export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

pyenv install 3.5.2
pyenv local 3.5.2


virtualenv -p python3 venv
. ./venv/bin/activate
pip install -r requirements.txt
