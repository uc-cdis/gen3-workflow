# Deployment to a Gen3 Instance

Gen3Workflow (using [Funnel](https://ohsu-comp-bio.github.io/funnel) as the TES server) can be deployed to a Helm-based Gen3 instance by following these steps.

---

## Enable Gen3Workflow and required secrets

Enable the Gen3Workflow service in your `values.yaml` and configure secrets as detailed below.
Setting `gen3-workflow.enabled: true` triggers the deployment of both Gen3Workflow and Funnel.

```yaml
global:
  externalSecrets:
    deploy: true
    createLocalK8sSecret: false
    pushSecret: true
  postgres:
    externalSecret: "<name of master Postgres secret in AWS Secrets Manager>"
  clusterName: "<name of the eks cluster where the gen3 instance is deployed>"

gen3-workflow: # <-- configure the Gen3Workflow chart
  enabled: true
  externalSecrets:
    gen3workflowG3auto: "<namespace>-gen3workflow-g3auto"

funnel: # <-- configure the Gen3 Funnel chart
  postgres:
    dbCreate: true
  externalSecrets:
    dbcreds: "<namespace>-funnel-creds"
    funnelOidcClient: "<namespace>-funnel-oidc-client"
  funnel: # <-- configure the OHSU Funnel chart
    Kubernetes:
      JobsNamespace: "workflow-pods-<namespace>"
```

> **Technical details**
>
> For more details on how the Helm chart is designed, refer to the [Helm Chart Architecture](helm_chart_architecture.md) document.
>
> - *Secrets*
>
> See [this documentation](https://github.com/uc-cdis/gen3-helm/blob/3640fd1/docs/databases.md#values-for-enabling-pushsecret-bootstrap) for additional details about the secrets setup.
>
> - *JobsNamespace*
>
> When a new task is created, Funnel provisions Kubernetes resources (pods, PVCs, jobs, etc.) to execute the workload. For improved security and isolation, these resources can be created in a separate namespace. The Gen3Workflow Helm chart includes the necessary network policies to ensure that only the required pods are able to communicate with each other.
> Naming Convention: Funnel supports any Kubernetes-compatible value for `JobsNamespace`. However, when using Funnel together with Gen3Workflow, a specific naming convention ("workflow-pods-\<release-namespace\>") is required and enforced, to ensure correct integration and expected behavior between Gen3Workflow and Funnel. Using a different value may result in deployment issues or unexpected runtime behavior.
>
> - *Funnel Dependency and OIDC Client Setup*
>
> Deploying Gen3Workflow automatically creates a `funnel-dbcreate` job, which creates a Postgres database for Funnel in AWS RDS.
>
> Deploying Gen3Workflow also automatically creates a `funnel-oidc-job`, which creates a Fence client for the Funnel plugin and stores the client ID and secret in a `funnel-oidc-client` Kubernetes secret.
> Note: The value `funnel.externalSecrets.funnelOidcClient` can be overridden to use a different secret name when external secrets are enabled. It is typically configured using the pattern: `<namespace>-funnel-oidc-client`.
>
> - *Cluster Configuration Requirement*
>
> Gen3Workflow requires the Gen3 Helm chart’s `.Values.global.clusterName` to be set to the name of the Amazon EKS cluster where Gen3 is deployed. While Gen3 strives to remain cloud-agnostic, Gen3Workflow currently requires Amazon EKS for supported operation. This value must be configured correctly to ensure proper deployment and integration.


---

## Configure Gen3Workflow

The default configuration is available [here](https://github.com/uc-cdis/gen3-helm/blob/03227ec/helm/gen3-workflow/values.yaml#L283). You can customize Gen3Workflow by overriding values under `gen3WorkflowConfig` in your `values.yaml`, for example:
```yaml
gen3-workflow:
  [...]
  gen3WorkflowConfig:
    debug: true
```

---

## IAM Permissions (Crossplane vs Manual Setup)

Gen3Workflow requires specific IAM roles and policies.

Crossplane can be enabled by updating `.Values.global.crossplane`. More information [here](https://github.com/uc-cdis/gen3-helm/blob/03227ec/helm/gen3/values.yaml#L42).

* If **Crossplane is enabled**, these resources are created automatically during Helm deployment.
* If **Crossplane is not enabled**, you must create them manually using this Helm template as reference:
  [gen3-workflow/templates/crossplane.yaml](https://github.com/uc-cdis/gen3-helm/blob/03227ec/helm/gen3-workflow/templates/crossplane.yaml)
  * Also, one needs to update `.Values.serviceAccount.annotations` to include the role-arn that must be assigned to the gen3-workflow's service account.
  ```
  eks.amazonaws.com/role-arn: <iam-role-arn>
  ```

---

## Authorization Setup

* Update your `user.yaml` as described in the [authorization guide](authorization.md).
* After updating, run the `usersync` job to apply the changes.

---

## Test the deployment
* Follow the steps in [Run Nextflow workflows with Gen3Workflow](local_installation.md#run-nextflow-workflows-with-gen3workflow) to test the deployment using Nextflow workflows.
* When deploying Gen3Workflow to a Gen3 instance, ensure `Gen3Workflow URL` is set to your commons' endpoint URL.
---

## Automation notes

> TODO: check if this is still accurate

Some manual steps are currently necessary to deploy Gen3Workflow to a new Gen3 instance.

- Karpenter resources for workflows

We need to deploy karpenter resources for workflow per-user. We have generic workflow resources deployed, but they are not tested, and should ideally not be used. More context [here](https://cdis.slack.com/archives/CLZJVC38B/p1738882314962669?thread_ts=1738880648.216489&cid=CLZJVC38B).

- S3 mountpoint

We need to make sure the S3 mountpoint is configured correctly, and ideally we should have per-pod identity so that the workflows can use per-user buckets. See [this](https://github.com/awslabs/mountpoint-s3-csi-driver/issues/334#issuecomment-2613552946). More context [here](https://cdis.slack.com/archives/CLZJVC38B/p1738882570732499?thread_ts=1738880648.216489&cid=CLZJVC38B).

- s3-csi-driver IAM policy

The new buckets created by Gen3Workflow must be added to the s3-csi-driver IAM policy. Ideally when the code creates the bucket, we also create a role per user that we can use [this](https://aws.amazon.com/about-aws/whats-new/2024/10/mountpoint-amazon-s3-csi-driver-access-controls-kubernetes-pods/) for. And if we can generate [NodeClasses](https://karpenter.sh/docs/concepts/nodeclasses/) and [NodePools](https://karpenter.sh/docs/concepts/nodepools/) per user and tell the workflow pods to only run on these nodes, we will get cost tracking as well (that's what we do for Argo workflows). More context [here](https://cdis.slack.com/archives/CLZJVC38B/p1738965383510779?thread_ts=1738947430.566729&cid=CLZJVC38B) and [here](https://docs.google.com/document/d/1nTn4XB6e33-BAnSqGsptzzBm3-ZSNHq4DXlwNxLN1VE).
