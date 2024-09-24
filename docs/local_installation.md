# Local installation

## Install Gen3Workflow

Install required software:

*   [Python](https://www.python.org/downloads/) 3.9.x
*   [Poetry](https://poetry.eustace.io/docs/#installation)

Then use `poetry install` to install the dependencies. Before that,
a [virtualenv](https://virtualenv.pypa.io/) is recommended.
If you don't manage your own, Poetry will create one for you
during `poetry install`, and you must activate it with `poetry shell`.
You may also need to upgrade `pip` to the latest version.

## Create configuration file

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

## Run Gen3Workflow

Update your configuration file to set `LOCAL_MIGRATION` to `true`, so that no attempts to interact with Arborist are made.

Run database schema migration:

```bash
alembic upgrade head
```

Run the server with auto-reloading:

```bash
python run.py
OR
uvicorn gen3workflow.asgi:app --reload
```

Try out the API at <http://localhost:8000/_status> or <http://localhost:8000/docs> (you might have to set `DOCS_URL_PREFIX` to `""` in your configuration file for the docs endpoint to work).

### Quickstart with Helm

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

Deploying Gen3Workflow this way will use the defaults that are defined in this [values.yaml file](https://github.com/uc-cdis/gen3-helm/blob/master/helm/gen3workflow/values.yaml)

You can learn more about these values by accessing the Gen3Workflow [README.md](https://github.com/uc-cdis/gen3-helm/blob/master/helm/gen3workflow/README.md)

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
Gen3Workflow relies on Arborist to run. Please view the [Arborist Quick Start Guide](https://github.com/uc-cdis/arborist) for more information.
