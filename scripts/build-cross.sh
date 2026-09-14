#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"

mkdir -p "${DIST_DIR}"

build_arch() {
    local arch="$1"
    local docker_platform=""
    case "${arch}" in
        x86_64)
            docker_platform="linux/amd64"
            ;;
        aarch64)
            docker_platform="linux/arm64"
            ;;
        *)
            echo "Unsupported arch: ${arch}" >&2
            exit 1
            ;;
    esac

    echo "=== Building netqmon-agent for ${arch} (${docker_platform}) ==="
    local image_tag="netqmon-agent-builder:${arch}"
    docker build \
        --platform "${docker_platform}" \
        -f "${ROOT_DIR}/deploy/docker/Dockerfile.agent" \
        -t "${image_tag}" \
        "${ROOT_DIR}"

    local container_id
    container_id=$(docker create --platform "${docker_platform}" "${image_tag}")
    docker cp "${container_id}:/netqmon-agent" "${DIST_DIR}/netqmon-agent_${arch}"
    docker rm -v "${container_id}"
    chmod 0755 "${DIST_DIR}/netqmon-agent_${arch}"

    echo "Building OpenWrt .ipk package for ${arch}..."
    "${ROOT_DIR}/packaging/openwrt/build-ipk.sh" \
        "${DIST_DIR}/netqmon-agent_${arch}" \
        "${arch}" \
        "0.1.0-1" \
        "${DIST_DIR}"
}

ARCH_TARGET="${1:-all}"
if [[ "${ARCH_TARGET}" == "all" ]]; then
    build_arch x86_64
    build_arch aarch64
else
    build_arch "${ARCH_TARGET}"
fi

echo "=== Build artifacts generated in ${DIST_DIR} ==="
ls -la "${DIST_DIR}"
