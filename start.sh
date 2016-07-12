#!/bin/bash
cd "$(dirname "$(readlink -f "$(command -v "$0")")")"
. ./venv/bin/activate
exec ./ms-ff-uag-tcp "$@"
