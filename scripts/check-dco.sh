#!/bin/sh
# DCO sign-off check: ensures the commit message contains a Signed-off-by trailer.
# Invoked by pre-commit hook on commit-msg stage.

if ! grep -q "^Signed-off-by:" "$1"; then
    echo "Error: commit message must contain 'Signed-off-by:' trailer"
    echo "Use 'git commit -s' to automatically add it"
    exit 1
fi
exit 0
