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

Gen3Workflow requires some access in AWS to function properly.

Crossplane can be enabled by updating `.Values.global.crossplane`. More information [here](https://github.com/uc-cdis/gen3-helm/blob/03227ec/helm/gen3/values.yaml#L42).

* If **Crossplane is enabled**, these resources are created automatically during Helm deployment.
* If **Crossplane is not enabled**, you can create them manually using [this Helm template](https://github.com/uc-cdis/gen3-helm/blob/master/helm/gen3-workflow/templates/crossplane.yaml) as reference.

> In CTDS environments, the recommendation is to use Crossplane for Dev and QA environments and Terraform/Terragrunt for Production environments. Check out [this internal link](https://github.com/uc-cdis/gen3-terragrunt/pull/251/changes) for an example of creating this role with Terragrunt.

Once the role is created, add it to your configuration:
```yaml
gen3-workflow:
  [...]
  serviceAccount:
    annotations:
      eks.amazonaws.com/role-arn: "arn:aws:iam::123456789:role/my-gen3-workflow-role"
```

---

## Authorization Setup

* Update your `user.yaml` as described in the [authorization guide](authorization.md).
* After updating, run the `usersync` job to apply the changes.

---

## Test the deployment
* Follow the steps in [Run Nextflow workflows with Gen3Workflow](local_installation.md#run-nextflow-workflows-with-gen3workflow) to test the deployment using Nextflow workflows.
* When deploying Gen3Workflow to a Gen3 instance, ensure `Gen3Workflow URL` is set to your commons' endpoint URL.
