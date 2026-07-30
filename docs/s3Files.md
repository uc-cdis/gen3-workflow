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


### Determining the EKS Security Group Names for S3 Files Setup

`gen3-workflow` needs the names of the EKS security groups attached to the nodes that run workflow tasks, in order to allow S3 Files mount targets network access. These are currently **not derivable programmatically** and must be looked up manually per cluster, then set as config values.

**Steps for a Gen3 operator:**

1. **Identify the node role(s) workflow tasks run on** for this environment. In most clusters this is `role=workflow` (and `role=gpu` if GPU tasks are supported). Check the cluster's `gen3-gitops` `cluster-values.yaml` for how these roles are configured, since role → security-group mapping can differ per environment.

2. **Find the Karpenter `EC2NodeClass` for each relevant role** in `gen3-helm` under `helm/cluster-level-resources/templates/karpenter-config-resources-<role>.yaml` (e.g. `karpenter-config-resources-workflow.yaml`). Look at the `securityGroupSelectorTerms` block — nodes get whichever security groups carry the matching `karpenter.sh/discovery` tag value (`selectorTag` from Helm values).

3. **Query AWS for the security groups carrying that discovery tag**, scoped to the cluster's VPC:
   ```
   aws ec2 describe-security-groups \
     --filters "Name=tag:karpenter.sh/discovery,Values=<selectorTag>" \
     --query "SecurityGroups[].{Name:GroupName,Id:GroupId}"
   ```

4. **Manually identify the "main" security group** from the results — the one that actually holds the cluster's inbound/outbound networking rules (as opposed to any minimal/placeholder groups also carrying the tag). This step is judgment-based today; usually the one with most inbound and outbound rules.

5. Repeat for each role that can run workflow tasks. Note: in `devplanetv2`, nodes labeled `role=workflow` carry the same discovery tag as jupyter nodes, so the jupyter security group ends up governing traffic for workflow nodes — check whether your cluster has the same overlap before assuming you only need one SG name.

6. Set the resulting security group name(s) in the `gen3-workflow` config under the field `EKS_SECURITY_GROUP_NAMES`.

> **Known limitation:** this is a temporary, manually-maintained workaround. The long-term plan is to move nodepool (and likely security group) creation into `gen3-workflow` itself once per-user nodepools are implemented, at which point this lookup process should be revisited/removed.
