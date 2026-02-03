# Deployment to a Gen3 Instance

**Gen3Workflow** (using [Funnel](https://ohsu-comp-bio.github.io/funnel) as the TES server) can be deployed to a Helm-based Gen3 instance by following these steps.

---

## 1. Enable Gen3Workflow

Enable the service in your `values.yaml`:

```yaml
gen3-workflow:
  enabled: true
```

---

## 2. Configure Gen3Workflow

You can customize Gen3Workflow by overriding values under `gen3WorkflowConfig` in your `values.yaml`.

The default configuration is available here:
[gen3-workflow/values.yaml#L308](https://github.com/uc-cdis/gen3-helm/blob/master/helm/gen3-workflow/values.yaml#L308)
(See `.Values.gen3WorkflowConfig`)

---

## 3. Funnel Dependency and OIDC Client Setup

Deploying Gen3Workflow automatically creates a **funnel-oidc-job**, which:

* Creates a Fence client for the Funnel plugin
* Stores the client ID and secret in a Kubernetes secret named: `funnel-oidc-client`

> **Note:**
> The value `gen3-workflow.externalSecrets.funnelOidcClient` can be overridden to use a different secret name when external secrets are enabled.
> This is typically configured by the PE team using the pattern:
>
> ```
> <env_name>-funnel-oidc-client
> ```

---

## 4. IAM Permissions (Crossplane vs Manual Setup)

Gen3Workflow requires specific IAM roles and policies.

* If **Crossplane is enabled**, these resources are created automatically during Helm deployment.
* If **Crossplane is not enabled**, you must create them manually using this Helm template as reference:
  [gen3-workflow/templates/crossplane.yaml](https://github.com/uc-cdis/gen3-helm/blob/master/helm/gen3-workflow/templates/crossplane.yaml)
  * Also, one needs to update `.Values.serviceAccount.annotations` to include the role-arn that must be assigned to the gen3-workflow's service account.
  ```
  eks.amazonaws.com/role-arn: <iam-role-arn>
  ```

- Note: Crossplane can be enabled by updating `.Values.global.crossplane`. More information [here](https://github.com/uc-cdis/gen3-helm/blob/master/helm/gen3/values.yaml#L39)
---

## 5. Authorization Setup

Update your `user.yaml` as described in the authorization guide:
* [Authorization Documentation](authorization.md)

After updating, run the `usersync` job to apply the changes.

---

## 6. Configure Jobs Namespace (Required)

When a new task is created, Funnel provisions Kubernetes resources (pods, PVCs, jobs, etc.) to execute the workload.

For improved **security and isolation**, these resources can be created in a **separate namespace**. The Gen3Workflow Helm chart includes the necessary **network policies** to ensure that only the required pods are able to communicate with each other.

To enable this, you **must override the following value** in your `values.yaml`:

```yaml
gen3WorkflowConfig:
    funnel:
        Kubernetes:
            jobsNamespace: <jobs-namespace>
```

**Recommendation:**
Use a naming convention such as: `workflow-pods-<release-namespace>`

Example:

```yaml
gen3WorkflowConfig:
    funnel:
        Kubernetes:
            jobsNamespace: workflow-pods-qa-midrc
```

### 7. Helm Chart architecture
* More information regarding how the helm chart is designed can be found in this document -- [WIP-Placeholder link](#placeholder_link)

---

## Documentation WIP

9. Follow [these steps](local_installation.md#run-nextflow-workflows-with-gen3workflow) to test the deployment.

## Automation notes

Some manual steps are currently necessary to deploy Gen3Workflow to a new Gen3 instance.

- Karpenter resources for workflows

We need to deploy karpenter resources for workflow per-user. We have generic workflow resources deployed, but they are not tested, and should ideally not be used. More context [here](https://cdis.slack.com/archives/CLZJVC38B/p1738882314962669?thread_ts=1738880648.216489&cid=CLZJVC38B).

- S3 mountpoint

We need to make sure the S3 mountpoint is configured correctly, and ideally we should have per-pod identity so that the workflows can use per-user buckets. See [this](https://github.com/awslabs/mountpoint-s3-csi-driver/issues/334#issuecomment-2613552946). More context [here](https://cdis.slack.com/archives/CLZJVC38B/p1738882570732499?thread_ts=1738880648.216489&cid=CLZJVC38B).

- s3-csi-driver IAM policy

The new buckets created by Gen3Workflow must be added to the s3-csi-driver IAM policy. Ideally when the code creates the bucket, we also create a role per user that we can use [this](https://aws.amazon.com/about-aws/whats-new/2024/10/mountpoint-amazon-s3-csi-driver-access-controls-kubernetes-pods/) for. And if we can generate [NodeClasses](https://karpenter.sh/docs/concepts/nodeclasses/) and [NodePools](https://karpenter.sh/docs/concepts/nodepools/) per user and tell the workflow pods to only run on these nodes, we will get cost tracking as well (that's what we do for Argo workflows). More context [here](https://cdis.slack.com/archives/CLZJVC38B/p1738965383510779?thread_ts=1738947430.566729&cid=CLZJVC38B).
