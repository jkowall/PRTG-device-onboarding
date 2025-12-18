#!/bin/bash
set -e

echo "Running Pylint..."
# Fail if score is under 8.0, or if there are errors (E) or fatal (F) messages
if [ -f "./venv/bin/pylint" ]; then
    PYLINT="./venv/bin/pylint"
else
    PYLINT="pylint"
fi

$PYLINT --fail-under=8.0 prtg_manager.py
