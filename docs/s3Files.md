# S3 Files Setup

## Overview
TES worker and executor pods use **S3 Files** (Amazon's EFS-backed service) to interact with a user's S3 bucket. While pod lifecycle is managed by the underlying execution engine (Funnel), Gen3Workflow is responsible for provisioning the supporting AWS resources — file systems, mount targets, IAM roles, and security groups — required for S3 Files to function.

## Enabling S3 Files
Set the following in your config:

```yaml
ENABLE_S3_FILES: true
```

For Helm-based deployments, set:

```yaml
{{ .Values.gen3WorkflowConfig.enableS3Files }}: true
```

## Prerequisites
* Gen3Workflow must be deployed on an EKS cluster.
* The EKS cluster must support S3 Files, provisioned via the [EFS CSI driver](https://github.com/kubernetes-sigs/aws-efs-csi-driver).


#### NOTE:
* Currently Gen3Workflow with S3Files only supports user bucket and the EKS cluster being present in the same region. Support shall be added in the future.
