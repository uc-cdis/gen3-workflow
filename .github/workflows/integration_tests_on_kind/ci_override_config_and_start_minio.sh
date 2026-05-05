#!/usr/bin/env bash
set -Eeuo pipefail

# Override the HOSTNAME and HOSTNAME_PROTOCOL set by the CI workflow.
# The Kind cluster will be exposed at http://localhost:8000
echo "HOSTNAME=localhost:8000" >> $GITHUB_ENV
echo "HOSTNAME_PROTOCOL=http" >> $GITHUB_ENV

MINIO_SERVICE_URL="http://minio.${NAMESPACE}.svc.cluster.local:9000"

# Keep the config files for the services we need, delete the rest
cd gen3-gitops-ci/ci/default/values && mkdir ../to-keep
mv arborist.yaml fence.yaml funnel.yaml gen3-workflow.yaml indexd.yaml revproxy.yaml values.yaml ../to-keep
rm ./* && mv ../to-keep/* .

yq eval -i '.gen3-workflow.enabled = true' gen3-workflow.yaml
MINIO_SERVICE_URL=$MINIO_SERVICE_URL yq eval -i '.gen3-workflow.gen3WorkflowConfig.s3UpstreamEndpoint = strenv(MINIO_SERVICE_URL)' gen3-workflow.yaml
yq eval -i '.gen3-workflow.gen3WorkflowConfig.s3AccessKeyId = "minioadmin"' gen3-workflow.yaml
yq eval -i '.gen3-workflow.gen3WorkflowConfig.s3SecretAccessKey = "minioadmin"' gen3-workflow.yaml
# disable KMS encryption - it might be doable with Minio KMS if we want to enable it in the future
yq eval -i '.gen3-workflow.gen3WorkflowConfig.kmsEncryptionEnabled = false' gen3-workflow.yaml
# kind clusters do not have nodepools
yq eval -i '.gen3-workflow.gen3WorkflowConfig.enableOptimizedNodeScheduling = false' gen3-workflow.yaml

# overwrite gen3-workflow config `EKS_CLUSTER_NAME` to an empty string
yq eval -i '.global.clusterName = ""' values.yaml

# update fence and indexd configs to generate secrets instead of looking for pre-existing secrets.
# update fields in the private fence config because it takes precedence over the public config.
yq eval -i '.indexd.externalSecrets.createK8sServiceCredsSecret = "true"' indexd.yaml
cat <<EOF > temp-fence.yaml
fence:
  externalSecrets:
    createK8sFenceConfigSecret: "true"
    createK8sGoogleAppSecrets: "true"
    createK8sJwtKeysSecret: "true"
  usersync:
    userYamlS3Endpoint: ${MINIO_SERVICE_URL}
    userYamlS3AccessKeyId: minioadmin
    userYamlS3SecretAccessKey: minioadmin
    syncFromDbgap: false
  FENCE_CONFIG:
    BASE_URL: 'http://fence-service.${NAMESPACE}.svc.cluster.local'
    OPENID_CONNECT:
      fence:
        api_base_url: ''
        client_id: 'abc'
        client_secret: 'xyz'
      ras:
        discovery_url: 'https://stsstg.nih.gov/.well-known/openid-configuration'
        client_id: 'abc'
        client_secret: 'xyz'
        redirect_url: '{{BASE_URL}}/login/ras/callback'
      google:
        discovery_url: 'https://accounts.google.com/.well-known/openid-configuration'
        client_id: 'abc'
        client_secret: 'xyz'
        redirect_url: '{{BASE_URL}}/login/google/login/'
    AWS_CREDENTIALS:
      cdistest:
        aws_access_key_id: 'abc'
        aws_secret_access_key: 'xyz'
EOF
yq eval-all -i 'select(fileIndex == 0) * select(fileIndex == 1)' fence.yaml temp-fence.yaml
rm temp-fence.yaml

# Configure Funnel to use Minio, reset Funnel settings that do not work in a Kind cluster,
# and reset the DB config so Funnel uses a local postgres pod:
# https://github.com/uc-cdis/ohsu-funnel-helm-charts/blob/b4095e4/charts/funnel/values.yaml#L274-L278
yq eval -i '.funnel.postgres.dbCreate = false' funnel.yaml
yq eval -i '.funnel.funnel.postgresql.enabled = false' funnel.yaml
yq eval -i '.funnel.funnel.Kubernetes.NodeSelector = {}' funnel.yaml
yq eval -i '.funnel.funnel.Kubernetes.Tolerations = []' funnel.yaml
yq eval -i '.funnel.funnel.Kubernetes.Worker.PriorityClassName = ""' funnel.yaml
# Configure `endpoint_url`, `authenticationSource` and `stsRegion` so the PVs talk to Minio
# instead of AWS S3.
MINIO_SERVICE_URL=$MINIO_SERVICE_URL yq eval -i '.funnel.funnel.endpoint_url = strenv(MINIO_SERVICE_URL)' funnel.yaml
yq eval -i '.funnel.funnel.authenticationSource = "driver"' funnel.yaml
yq eval -i '.funnel.funnel.stsRegion = ""' funnel.yaml

# Disable unnecessary services. Master list:
# https://github.com/uc-cdis/gen3-gitops/tree/160a135/ci/default/values
# (this could also be done automatically by using `--set` for all `<service>.enabled` in
# the `helm install` command)
# "zzz-" file name hack so it's the last file to be processed and these values override
# previous ones.
cat <<EOF > zzz-disable-services.yaml
access-backend:
  enabled: false
ambassador:
  enabled: false
"argo-wrapper:":
  enabled: false
audit:
  enabled: false
cedar:
  enabled: false
cohort-middleware:
  enabled: false
dicom-server:
  enabled: false
etl:
  enabled: false
frontend-framework:
  enabled: false
gen3-user-data-library:
  enabled: false
guppy:
  enabled: false
hatchery:
  enabled: false
manifestservice:
  enabled: false
metadata:
  enabled: false
ohif-viewer:
  enabled: false
orthanc:
  enabled: false
peregrine:
  enabled: false
portal:
  enabled: false
requestor:
  enabled: false
sheepdog:
  enabled: false
sower:
  enabled: false
ssjdispatcher:
  enabled: false
wts:
  enabled: false
EOF

# deploy MinIO
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: minio
  namespace: ${NAMESPACE}
  labels:
    app: minio
spec:
  containers:
    - name: minio
      image: quay.io/minio/minio:latest-cicd
      args:
        - server
        - /data
      env:
        - name: MINIO_ROOT_USER
          value: minioadmin
        - name: MINIO_ROOT_PASSWORD
          value: minioadmin
      ports:
        - containerPort: 9000
---
apiVersion: v1
kind: Service
metadata:
  name: minio
  namespace: ${NAMESPACE}
spec:
  selector:
    app: minio
  ports:
    - port: 9000
      targetPort: 9000
EOF

# external-secrets is required to install gen3 and is not installed out of the box in kind clusters
helm repo add external-secrets https://charts.external-secrets.io
helm repo update
helm install external-secrets external-secrets/external-secrets -n external-secrets --create-namespace --set installCRDs=true --version 0.8.5

# Install aws-mountpoint-s3-csi-driver. The driver reads S3 credentials from `aws-secret`.
# see https://github.com/awslabs/mountpoint-s3-csi-driver/blob/db678c1/docs/CONFIGURATION.md#driver-level-credentials-with-kubernetes-secrets
kubectl create secret generic aws-secret --namespace kube-system --from-literal "key_id=minioadmin" --from-literal "access_key=minioadmin" --from-literal "session_token="
# The mount-s3 pods also need access to Minio.
cat <<EOF > values-kind.yaml
mountpointPod:
  namespace: mount-s3
  env:
    - name: AWS_ACCESS_KEY_ID
      valueFrom:
        secretKeyRef:
          name: aws-secret
          namespace: kube-system
          key: key_id
    - name: AWS_SECRET_ACCESS_KEY
      valueFrom:
        secretKeyRef:
          name: aws-secret
          namespace: kube-system
          key: access_key
EOF
helm repo add aws-mountpoint-s3-csi-driver https://awslabs.github.io/mountpoint-s3-csi-driver
helm repo update
helm upgrade --install aws-mountpoint-s3-csi-driver --namespace kube-system aws-mountpoint-s3-csi-driver/aws-mountpoint-s3-csi-driver -f values-kind.yaml

kubectl wait -n ${NAMESPACE} --for=condition=Ready pod/minio --timeout=120s
kubectl wait -n external-secrets --for=condition=Ready pod --all --timeout=120s
kubectl wait -n kube-system --for=condition=Ready pod --all --timeout=120s

# user.yaml file which will be used by the usersync job
cat <<EOF > user.yaml
authz:
  policies:
    - id: gen3_workflow_user
      description: Allows the creation of workflow tasks
      role_ids:
        - gen3_workflow_creator
      resource_paths:
        - /services/workflow/gen3-workflow/tasks
    - id: gen3_workflow_storage_admin
      description: Allows access to manage all the user buckets
      role_ids:
        - gen3_workflow_admin
      resource_paths:
        - /services/workflow/gen3-workflow/storage
  resources:
    - name: services
      subresources:
        - name: workflow
          subresources:
            - name: gen3-workflow
              subresources:
                - name: tasks
                - name: storage
  roles:
    - id: gen3_workflow_reader
      permissions:
        - id: gen3_workflow_reader_action
          action:
            service: gen3-workflow
            method: read
    - id: gen3_workflow_creator
      permissions:
        - id: gen3_workflow_creator_action
          action:
            service: gen3-workflow
            method: create
    - id: gen3_workflow_admin
      permissions:
        - id: gen3_workflow_admin_action
          action:
            service: gen3-workflow
            method: "*"
clients:
  funnel-plugin-client:
    policies:
      - gen3_workflow_storage_admin
users:
  main@example.org:
    admin: true
    policies:
      - gen3_workflow_user
  indexing@example.org: {}
  user0@example.org:
    admin: false
    policies:
      - gen3_workflow_user
  user1@example.org: {}
  user2@example.org: {}
  dummy-one@example.org: {}
  smarty-two@example.org: {}
EOF

# minio port-forward to create the bucket and upload the user.yaml file
kubectl port-forward -n "${NAMESPACE}" service/minio 9000:9000 &
PF_PID=$!
trap "kill $PF_PID" EXIT  # kill port-forward when script exits
sleep 2  # wait for port-forward to be ready

# upload the user.yaml file
aws configure set endpoint_url http://localhost:9000
aws configure set aws_access_key_id minioadmin
aws configure set aws_secret_access_key minioadmin
aws s3 mb s3://cdis-gen3-users
aws s3 cp user.yaml s3://cdis-gen3-users/ci/
