#!/usr/bin/env bash

set -e

. venv/bin/activate

pip install -U -r requirements.txt
rstcheck --report warning README.rst
rm -rf dist/ build/
python3 setup.py sdist
python3 setup.py bdist_wheel
