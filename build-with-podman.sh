#!/bin/sh

set -e

readonly IMAGE_NAME=luna-pkcv-builder
readonly CONTAINER_NAME=${IMAGE_NAME}
readonly INPUT_DIRECTORY=./src
readonly OUTPUT_DIRECTORY=./target

podman build \
    --file "./Containerfile" \
    --tag "${IMAGE_NAME}" \
    .

mkdir -p "${OUTPUT_DIRECTORY}"

podman run \
    --replace \
    --rm \
    --volume "${INPUT_DIRECTORY}":/luna/src:ro \
    --volume "${OUTPUT_DIRECTORY}":/luna/target:rw \
    --security-opt label=disable \
    --name "${CONTAINER_NAME}" \
    "${IMAGE_NAME}"
