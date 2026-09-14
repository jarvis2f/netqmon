#!/bin/sh
set -eu

wget -q -O /dev/null http://127.0.0.1:8091/internal/health
wget -q -O /dev/null http://127.0.0.1:3000/login
