#!/usr/bin/env bash
# -----
# -v VERSION

set -ex

VERSION="BETA"

while [[ $# -gt 0 ]]
do
  case "$1" in
    "--version")
      VERSION="$2"
      shift
      ;;
    *)
      echo "$1 $0 -v|--version" && exit 1
      ;;
  esac
  shift
done

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
application=bridgekeeper
service=api
ghcrio_image_name=ghcr.io/klaasjanelzinga/${application}/${service}

(cd $script_dir/.. && docker build -t ${ghcrio_image_name}:$VERSION -f docker-files/Dockerfile .)
docker tag ${ghcrio_image_name}:$VERSION ${ghcrio_image_name}:latest
docker push ${ghcrio_image_name}:$VERSION
docker push ${ghcrio_image_name}:latest
