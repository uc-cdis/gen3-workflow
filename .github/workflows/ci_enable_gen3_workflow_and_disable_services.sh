#!/usr/bin/env bash
set -Eeuo pipefail

# Minimal CI config override: enable gen3-workflow and disable services that are
# not needed for gen3-workflow integration tests.
#
# NOTE: This script is not referenced by any workflow in this repo, but it IS used in uc-cdis/funnel repo's integration tests.
# which passes it to the shared integration tests workflow as its CI config override script:
#   See SETUP_SCRIPT_2 in https://github.com/uc-cdis/funnel/blob/master/.github/workflows/gen3_integration_tests.yaml
# Do not delete or move it without updating those references.

cd gen3-gitops-ci/ci/default/values

yq eval -i '.gen3-workflow.enabled = true' gen3-workflow.yaml

# Disable unnecessary services. Master list:
# https://github.com/uc-cdis/gen3-gitops/tree/160a135/ci/default/values
# "zzz-" file name hack so it's the last file to be processed and these values override
# previous ones.
cat <<EOF > zzz-disable-services.yaml
access-backend:
  enabled: false
ambassador:
  enabled: false
"argo-wrapper:":
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
ohdsi-atlas:
  enabled: false
ohdsi-webapi:
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
zendesk-wrapper:
  enabled: false
EOF
