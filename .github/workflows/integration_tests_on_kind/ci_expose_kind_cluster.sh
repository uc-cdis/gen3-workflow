#!/usr/bin/env bash
set -Eeuo pipefail

# Allow Funnel executor pods to reach Fence. This runs after the Helm install because the
# `workflow-pods-${NAMESPACE}` namespace is created by the Helm chart. The matching ingress
# policy on the Fence pod is created in `ci_override_config_and_start_minio.sh`.
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: dev-funnel-executor-egress-to-fence-netpolicy
  namespace: workflow-pods-${NAMESPACE}
spec:
  podSelector:
    matchLabels:
      app: funnel-executor
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: ${NAMESPACE}
      podSelector:
        matchLabels:
          app: fence
EOF

# Expose the Kind cluster at http://localhost:8000
kubectl port-forward -n "${NAMESPACE}" service/revproxy-service 8000:80 &

# This ensures the port-forward command keeps running after the script exits, so the cluster
# stays accessible
disown $!

# Wait until the port is actually accepting connections
timeout 30 bash -c 'until nc -z localhost 8000; do sleep 0.5; done'
