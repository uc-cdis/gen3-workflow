# Use of IAM keys

Gen3Workflow generates and uses 2 sets of IAM keys: end user keys and system-managed keys.

When a user interacts with Gen3Workflow, 2 IAM users are created:
- `gen3wf-<hostname>-<user ID>` represents the end user
- `gen3wf-<hostname>-<user ID>-bot` represents the system

Contents:
- [End user keys](#end-user-keys)
  - [Expiration](#expiration)
- [System-managed keys](#system-managed-keys)
  - [Expiration](#expiration)

### End user keys

The end user can manage (create and delete) their own keys by using the `/storage/credentials` endpoints. Keys can only be viewed when the key is first generated; any calls to list the user's keys will only return the key ID, not the key itself.

The keys have access to an S3 bucket created for this user, and can be used to upload workflow inputs, download workflow outputs and access workflow intermediary files in general.

To run Nextflow workflows, the user should hit the `GET /storage/info` endpoint to get their AWS region and working directory, and configure them along with an IAM key in their Nextflow configuration, for example:

```
plugins {
	id 'nf-ga4gh'
}
process {
	executor = 'tes'
	container = 'quay.io/nextflow/bash'
}
tes {
	endpoint = 'http://localhost:8080/ga4gh/tes'
	oauthToken = "${GEN3_TOKEN}"
}
aws {
	accessKey = "${KEY_ID}"
	secretKey = "${KEY_SECRET}"
	region = '<region>'
}
workDir = '<working directory>'
```

It is recommended to set the key as environment variables instead of saving them in the configuration file. To run a workflow:
```
export KEY_ID=
export KEY_SECRET=
GEN3_TOKEN=xyz nextflow run hello
```

#### Expiration

End user keys are set to expire after a configured number of days. A daily cronjob should automatically delete any expired keys. It is the end user's responsibility to generate a new key for their workflows before the previous one expires.

### System-managed keys

IAM keys are required for the TES server to access workflow inputs and store workflow intermediary files and outputs in the user's S3 bucket. These keys are not visible to the end user. They are generated as needed and forwarded to the TES server when users create tasks.

#### Expiration

System-managed keys are set to expire after a configured number of days. A daily cronjob should automatically delete any expired keys. To avoid downtime for users' tasks, 2 system-managed keys are active at once. When the oldest key expires and is deleted, a new key is created. Gen3Workflow always forwards the newest system-managed key to the TES server.
