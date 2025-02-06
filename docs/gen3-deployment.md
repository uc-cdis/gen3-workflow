# Deployment to a Gen3 instance

Gen3Workflow (with Funnel as the TES server) can be deployed to a cloud-automation Gen3 instance by using the following steps.

1. Add the services to the manifest. The Funnel version can be "latest", or a specific Helm chart tag (`helm search repo ohsu --versions`).
```
"versions": {
    "gen3-workflow": "707767160287.dkr.ecr.us-east-1.amazonaws.com/gen3/gen3-workflow:master",
    "funnel": "latest"
}
```

2. Run `gen3 kube-setup-gen3-workflow`. This will create the Gen3Workflow and Funnel configuration files in `~/Gen3Secrets/g3auto/gen3workflow/`.

3. Deploying the services currently requires setting `KMS_ENCRYPTION_ENABLED: false` in `~/Gen3Secrets/g3auto/gen3workflow/gen3-workflow-config.yaml`. This will not be the case anymore once Funnel supports KMS encryption or custom worker plugins. You can also set the `TASK_IMAGE_WHITELIST` now to the list of images that are allowed. Update the configuration file, run `gen3 secrets sync` and `gen3 roll gen3-workflow`.

4. You may need to run `gen3 kube-setup-revproxy` before proceeding if revproxy has never been rolled with the Gen3Workflow routes.

5. Deploying the services currently requires the manual creation of an API key for Funnel to use, and only one username can be configured to run workflows. This will not be the case anymore once Funnel supports per-user buckets/credentials.
   1. Log in and visit `<Gen3 instance URL>/workflows/storage/info`.
   2. Copy the bucket name and the region.
   3. Create an IAM user with the policy below, and create an IAM key for this user.
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:*"
            ],
            "Resource": [
                "arn:aws:s3:::<bucket name provided by `/storage/info`>",
                "arn:aws:s3:::<bucket name provided by `/storage/info`>/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "kms:CreateKey",
                "kms:GenerateDataKey",
                "kms:CreateAlias",
                "kms:DescribeKey",
                "kms:TagResource"
            ],
            "Resource": "*"
        }
    ]
}
```

6. Update the `~/Gen3Secrets/g3auto/gen3workflow/funnel.conf` file:
```
AmazonS3:
  Key: <IAM key ID generated above>
  Secret: <IAM key secret generated above>
  Disabled: false

Kubernetes:
  Bucket: <bucket name provided by `/storage/info`>
  Region: <region provided by `/storage/info`>
```

7. Run `gen3 kube-setup-gen3-workflow`.

8. Update the `user.yaml` file as described in the [authorization documentation](authorization.md) and run the `usersync` job.

9. Follow [these steps](local_installation.md#run-nextflow-workflows-with-gen3workflow) to test the deployment.
