# Deployment to a Gen3 instance

Gen3Workflow (with [Funnel](https://ohsu-comp-bio.github.io/funnel) as the TES server) can be deployed to a cloud-automation Gen3 instance by using the following steps.

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

## Automation notes

Some manual steps are currently necessary to deploy Gen3Workflow to a new Gen3 instance.

- Karpenter resources for workflows

We need to deploy karpenter resources for workflow per-user. We have generic workflow resources deployed, but they are not tested, and should ideally not be used. More context [here](https://cdis.slack.com/archives/CLZJVC38B/p1738882314962669?thread_ts=1738880648.216489&cid=CLZJVC38B).

- S3 mountpoint

We need to make sure the S3 mountpoint is configured correctly, and ideally we should have per-pod identity so that the workflows can use per-user buckets. See [this](https://github.com/awslabs/mountpoint-s3-csi-driver/issues/334#issuecomment-2613552946). More context [here](https://cdis.slack.com/archives/CLZJVC38B/p1738882570732499?thread_ts=1738880648.216489&cid=CLZJVC38B).

- s3-csi-driver IAM policy

The new buckets created by Gen3Workflow must be added to the s3-csi-driver IAM policy. Ideally when the code creates the bucket, we also create a role per user that we can use [this](https://aws.amazon.com/about-aws/whats-new/2024/10/mountpoint-amazon-s3-csi-driver-access-controls-kubernetes-pods/) for. And if we can generate [NodeClasses](https://karpenter.sh/docs/concepts/nodeclasses/) and [NodePools](https://karpenter.sh/docs/concepts/nodepools/) per user and tell the workflow pods to only run on these nodes, we will get cost tracking as well (that's what we do for Argo workflows). More context [here](https://cdis.slack.com/archives/CLZJVC38B/p1738965383510779?thread_ts=1738947430.566729&cid=CLZJVC38B).
