# GPU support

## Usage

TES tasks can be run on a GPU node by using the special `_GPU` tag. For example:

```
{
  "name": "gpu-job",
  "tags": {"_GPU": "yes"},
  "executors": [
    {
      "image": "quay.io/nextflow/bash",
      "command": [
        "echo success!"
      ]
    }
  ]
}
```

## Configuration

This will only work if GPU nodes are available!

If running a Gen3 deployment through the Gen3 Helm chart, GPU nodes can be enabled by adding the **cluster** configuration below:
(See [this](https://github.com/uc-cdis/gen3-helm/blob/bbd9849/helm/cluster-level-resources/templates/karpenter-config-resources-gpu.yaml) and [this](https://github.com/uc-cdis/gen3-helm/blob/bbd9849/helm/cluster-level-resources/templates/nvidia-device-plugin.yaml))

```
karpenter-crds:
  gpu:
    enabled: true
    consolidation: true
    consolidateAfter: "30s"
    consolidationPolicy: "WhenEmpty"
    expireAfter: "168h"
    volumeSize: 80Gi
    additionalTags: {}
    requirements:
      - key: karpenter.sh/capacity-type
        operator: In
        values:
          - on-demand
      - key: kubernetes.io/arch
        operator: In
        values:
          - amd64

nvidia-device-plugin:
  enabled: true
  configuration:
    enabled: false
  targetRevision: v0.18.0
```

Funnel can then be configured to run jobs in the "gpu" nodepool:
(This is done automatically when using the special `_GPU` tag)

```
funnel:
    funnel:
        Kubernetes:
            NodeSelector: {"role": "gpu"}
            Tolerations:
                - Key: "nvidia.com/gpu"
                  Operator: "Equal"
                  Value: "present"
                  Effect: "NoSchedule"
```
