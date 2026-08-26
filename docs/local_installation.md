# Local installation

Contents:
- [Quickstart from source](#quickstart-from-source)
  - [Install Gen3Workflow](#install-gen3workflow)
  - [Create configuration file](#create-configuration-file)
  - [Start the Gen3Workflow service](#start-the-gen3workflow-service)
- [Run Nextflow workflows with Gen3Workflow](#run-nextflow-workflows-with-gen3workflow)
- [AWS access](#aws-access)
- [Quickstart with Helm](#quickstart-with-helm)

## Quickstart from source

### Install Gen3Workflow

Install required software:

*   [Python](https://www.python.org/downloads/) 3.13.x
*   [Poetry](https://poetry.eustace.io/docs/#installation)

Then use `poetry install` to install the dependencies. Before that,
a [virtualenv](https://virtualenv.pypa.io/) is recommended.
If you don't manage your own, Poetry will create one for you
during `poetry install`, and you must activate it with `poetry shell`.
You may also need to upgrade `pip` to the latest version.

### Create configuration file

Gen3Workflow requires a configuration file to run. We have a command line
utility to help you create one based on a default configuration.

The configuration file itself will live outside of this repo (to
prevent accidentally checking in sensitive information like database passwords).

To create a new configuration file from the default configuration:

```bash
python cfg_help.py create
```

This file will be placed in one of the default search directories for Gen3Workflow.

To get the exact path where the new configuration file was created, use:

```bash
python cfg_help.py get
```

The file should have detailed information about each of the configuration
variables. **Remember to fill out the new configuration file!**

To use a configuration file in a custom location, you can set the `GEN3WORKFLOW_CONFIG_PATH` environment variable.

### Start the Gen3Workflow service

You will need to run a TES server for Gen3Workflow to talk to. For example, you can start a local Funnel server: https://ohsu-comp-bio.github.io/funnel/#intro.

Update your configuration file:
- set `TES_SERVER_URL` to the TES server URL
- set `MOCK_AUTH` to `true`, so that no attempts to interact with Arborist are made.

Start the Gen3Workflow app:

```bash
python run.py
```

Try out the API at <http://localhost:8080/_status> or <http://localhost:8080/docs>.

> Note: Although the Gen3Workflow service can run as a standalone component, a complete end-to-end experience with Funnel and the Funnel plugin requires interaction with the Fence service. While support for this flow is planned for future releases, it is not currently supported out of the box.

## DPoP

The GA4GH TES and S3 endpoints support DPoP ([RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)). When it is enabled, an access token that is bound to a client's key - the auth service (e.g. Fence) marks it with a `cnf.jkt` claim - is only accepted if the request also carries a DPoP proof signed by the matching private key (demonstrating proof of possession).

Tokens that are not bound are unaffected, so worker pods using the `client_credentials` flow keep working.

To enable it, in your configuration file:
- set `DPOP_ENABLED` to `true`
- set `DPOP_REQUIRED` to `true` to reject any request to those endpoints that does not present a DPoP-bound token and a valid proof, rather than only enforcing the binding of tokens that have one.
- set `DPOP_EXEMPT_CLIENT_IDS` to the client IDs whose `client_credentials` tokens may reach those endpoints without a proof when `DPOP_REQUIRED` is `true`, for example the Funnel worker pods' client. Such a token is never DPoP-bound, so its holder has no key to sign a proof with. Leave the list empty and those clients are rejected too. An exempt token is an ordinary bearer credential: whoever holds it can act as any user the client is authorized for, and `DPOP_REQUIRED` does not change that - see [Authorization](authorization.md#client-credentials-and-dpop).
- set `DPOP_ALLOWED_ISSUERS` to the issuers allowed to sign the tokens, for example `["https://<commons hostname>/user"]`
- set `DPOP_SHARED_SECRET` to the **exact same value** as the auth service's `DPOP_SHARED_SECRET`, or set the `DPOP_SHARED_SECRET` environment variable, which takes precedence. Clients reuse the nonce the auth service handed them for their first request here, and a nonce signed with a different secret does not verify.
- if this service is not reached directly, set `DPOP_EXTERNAL_BASE_URL` to the URL clients use, and make sure `DPOP_PROTECTED_PATHS` maps each protected path prefix to the prefix the reverse proxy exposes it at. The Gen3 reverse proxy serves the S3 endpoint under `/workflows`, which it strips before forwarding, so the default configuration adds it back. Getting this wrong shows up as an `htu mismatch` error.

Optionally, set the `DPOP_NONCE_TTL` environment variable to change how long a nonce stays valid (defaults to 300 seconds).

Clients can generate the proofs with the [Gen3 Python SDK/CLI](https://github.com/uc-cdis/gen3sdk-python), which exchanges an API key for a bound token and then proxies Nextflow's TES and S3 traffic through freshly signed proofs.

## Run Nextflow workflows with Gen3Workflow

- Hit the `/storage/setup` endpoint to get your working directory
- Configure Nextflow. Example Nextflow configuration:
```
plugins {
	id 'nf-ga4gh'
}
process {
	executor = 'tes'
	container = 'quay.io/nextflow/bash'
}
tes {
	endpoint = '<Gen3Workflow URL>/ga4gh/tes'
	oauthToken = "${GEN3_TOKEN}"
}
aws {
	accessKey = "${GEN3_TOKEN}"
	secretKey = 'N/A'
	region = 'us-east-1'
	client {
		s3PathStyleAccess = true
		endpoint = '<Gen3Workflow URL>/s3'
	}
}
workDir = '<your working directory>'
```

A Gen3 access token is expected by most endpoints to verify the user's access (see [Authorization](authorization.md) documentation).

> The Gen3Workflow URL should be set to `http://localhost:8080` in this case; this is where the service runs by default when started with `python run.py`.

- Run a workflow:

When setting your token manually:
```
export GEN3_TOKEN=<your token>
nextflow run hello
```
Or, with the [Gen3 Python SDK](https://github.com/uc-cdis/gen3sdk-python) configured with an API key:
```
gen3 run nextflow run hello
```

## AWS access

For full functionality, the Gen3Workflow service requires access to perform a number of operations in AWS. The full policy can be found here: [gen3-workflow/templates/crossplane.yaml](https://github.com/uc-cdis/gen3-helm/blob/c9ad644/helm/gen3-workflow/templates/crossplane.yaml)

## Quickstart with Helm

You can now deploy individual services via Helm!

If you are looking to deploy all Gen3 services, that can be done via the Gen3 Helm chart.
Instructions for deploying all Gen3 services with Helm can be found [here](https://github.com/uc-cdis/gen3-helm#readme).

To deploy the Gen3Workflow service:
```bash
helm repo add gen3 https://helm.gen3.org
helm repo update
helm upgrade --install gen3/gen3workflow
```
These commands will add the Gen3 helm chart repo and install the Gen3Workflow service to your Kubernetes cluster.

Deploying Gen3Workflow this way will use the defaults that are defined in this [values.yaml file](https://github.com/uc-cdis/gen3-helm/blob/03227ec/helm/gen3workflow/values.yaml)

You can learn more about these values by accessing the Gen3Workflow [README.md](https://github.com/uc-cdis/gen3-helm/blob/03227ec/helm/gen3workflow/README.md)

If you would like to override any of the default values, simply copy the above values.yaml file into a local file and make any changes needed.

To deploy the service independant of other services (for testing purposes), you can set the .postgres.separate value to "true". This will deploy the service with its own instance of Postgres:
```bash
  postgres:
    separate: true
```

You can then supply your new values file with the following command:
```bash
helm upgrade --install gen3/gen3workflow -f values.yaml
```

If you are using Docker Build to create new images for testing, you can deploy them via Helm by replacing the .image.repository value with the name of your local image.
You will also want to set the .image.pullPolicy to "never" so kubernetes will look locally for your image.
Here is an example:
```bash
image:
  repository: <image name from docker image ls>
  pullPolicy: Never
  # Overrides the image tag whose default is the chart appVersion.
  tag: ""
```

Re-run the following command to update your helm deployment to use the new image:
```bash
helm upgrade --install gen3/gen3workflow
```

You can also store your images in a local registry. Kind and Minikube are popular for their local registries:
- https://kind.sigs.k8s.io/docs/user/local-registry/
- https://minikube.sigs.k8s.io/docs/handbook/registry/#enabling-insecure-registries

Dependencies:
* Gen3Workflow relies on Arborist to run. Please view the [Arborist Quick Start Guide](https://github.com/uc-cdis/arborist) for more information.
* Gen3Workflow also relies on [Funnel](https://ohsu-comp-bio.github.io/funnel) with [Funnel-gen3-plugin](https://github.com/uc-cdis/funnel-gen3-plugin) and [Fence]((https://github.com/uc-cdis/fence)).
