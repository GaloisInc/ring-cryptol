#!/bin/bash
set -e
# Bundle saw-script, crux-mir and mir-json in one package
TARGET_DIR=saw-suite
TARGET_OS=ubuntu-22.04-X64
UNZIP=1

# Fine Grained Read Only Token
TOKEN=${GITHUB_ACCESS_TOKEN}

# Preparation
rm -rf $TARGET_DIR
mkdir -p $TARGET_DIR
cd $TARGET_DIR

# saw-suite
TARGET=saw-suite-$TARGET_OS
ARTIFACT_ID=$(curl -s https://api.github.com/repos/galoisinc/saw-suite/actions/artifacts \
  | jq --arg target "$TARGET" '.artifacts | map(select(.name == $target)) | first | .id')
curl -L \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "https://api.github.com/repos/galoisinc/saw-suite/actions/artifacts/${ARTIFACT_ID}/zip" \
  --output $TARGET.zip

if [ $UNZIP -eq 1 ]; then
  echo "Unzipping $TARGET.zip!"
  unzip $TARGET.zip
  mv saw-suite/* .
  rm $TARGET.zip
  rmdir saw-suite
fi

echo "Downloaded on `date`" > TIMESTAMP.md

cd -
echo "Done! Saw suite saved into saw-suite directory"
