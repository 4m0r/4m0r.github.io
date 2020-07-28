#!/bin/bash
#
# Init the evrionment for new user.
#
# v2.5
# https://github.com/cotes2020/jekyll-theme-chirpy
# © 2020 Cotes Chung
# Published under MIT License

set -eu

_check_init() {
  if [[ -f .github/workflows/pages-deploy.yml ]]; then
    echo "Already initialized."
    exit 0
  fi
}

_check_init

rm -f .travis.yml
rm -rf .github/* _posts/* docs

mv .hook .github/workflows

git add -A  && git add .github -f
git commit -m "[Automation] Initialize the environment." -q

echo "[INFO] Initialization successful!"
