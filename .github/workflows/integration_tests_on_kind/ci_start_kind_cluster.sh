#!/usr/bin/env bash
set -Eeuo pipefail

curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.23.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind
kind version

CLUSTER_NAME=kind-cluster
K8S_VERSION=v1.35.0
NODE_IMAGE=kindest/node:${K8S_VERSION}

cat <<EOF | kind create cluster --name "$CLUSTER_NAME" --image "$NODE_IMAGE" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
EOF

kubectl wait --for=condition=Ready nodes --all --timeout=180s
