#!/usr/bin/env bash
# Builds the sandbox image for ARM64 (Fargate) and pushes it to the stack's ECR repository.
# Run after deploying the stack with SandboxEnabled=true (that creates the repository).
#   sandbox/push.sh [tag]        default tag: v1 (must match the SandboxImageTag stack parameter)
set -euo pipefail
REGION="${REGION:-ap-south-1}"
TAG="${1:-v1}"
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
aws ecr get-login-password --region "${REGION}" | docker login --username AWS --password-stdin "${REGISTRY}"
docker build --platform linux/arm64 -t "${REGISTRY}/pkgguard-sandbox:${TAG}" "$(cd "$(dirname "$0")" && pwd)"
docker push "${REGISTRY}/pkgguard-sandbox:${TAG}"
echo "pushed ${REGISTRY}/pkgguard-sandbox:${TAG}"
