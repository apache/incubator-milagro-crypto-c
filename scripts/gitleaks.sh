#!/bin/bash
#
# gitleaks.sh
#
# Detect secrets
#
# @author Kealan McCusker <kealanmccusker@gmail.com>
# ------------------------------------------------------------------------------

# NOTES:
#
# https://qredo.atlassian.net/wiki/spaces/SEC/pages/1002340428/Secret+Detection#Running-the-Secret-detection-locally
# https://github.com/zricethezav/gitleaks

# EXAMPLE USAGE:
#
# ./gitleaks.sh

set -Cue -o pipefail

PROJECT_HOME="$(cd "$(dirname "${0}")/.." && pwd)"
cd "$PROJECT_HOME"

function detect_secrets()
{
  # Check gitleaks image exists
  if [ ! "$(docker images | grep "^zricethezav/gitleaks .*latest")" ];
  then
      echo "docker pull ghcr.io/zricethezav/gitleaks:latest"
      docker pull ghcr.io/zricethezav/gitleaks:latest
  else
      echo "zricethezav/gitleaks:latest downloaded"
  fi

  # Get config file
  git clone git@gitlab.qredo.com:security/security-ci-cd-templates.git
  cp security-ci-cd-templates/secret-detection/qredo-secret-detection-config.toml  .

  # Run gitleaks
  docker run -v $PWD:/path zricethezav/gitleaks:latest detect --source="/path"  --verbose --config /path/qredo-secret-detection-config.toml --report-format json --report-path /path/gitleaks_report.json
}

detect_secrets
