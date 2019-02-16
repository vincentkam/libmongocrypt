#!/bin/sh

set -o xtrace

echo "Machine environment"
git --version
openssl version
python --version

if which gcc; then
    gcc --version
fi

if which clang; then
    clang --version
fi

cmake --version