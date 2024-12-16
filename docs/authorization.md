# Authorization

The Gen3 Workflow endpoints are protected by Arborist policies.

Contents:
- [GA4GH TES](#ga4gh-tes)
  - [Authorization configuration example](#authorization-configuration-example)

## GA4GH TES

- To create a task, users need `create` access to resource `/services/workflow/gen3-workflow/tasks` on service `gen3-workflow`.
- To view a task, users need `read` access to resource `/users/<user ID>/gen3-workflow/tasks/<task ID>` on service `gen3-workflow`.
  - Users are automatically granted access to `/users/<user ID>/gen3-workflow/tasks` so they can view their own tasks.
  - Admin access (the ability to see _all_ users’ tasks instead of just your own) can be granted to a user by granting them access to the parent resource `/services/workflow/gen3-workflow/tasks`.
  - This supports sharing tasks with others; for example, "user1" may share "taskA" with "user2" if the system grants "user2" access to `/users/user1/gen3-workflow/tasks/taskA`.

#### Authorization configuration example

```yaml
users:
  some-username:
    policies:
    - gen3_workflow_user

authz:
  resources:
  - name: services
    subresources:
    - name: workflow
      subresources:
      - name: gen3-workflow
        subresources:
        - name: tasks

  policies:
  - id: gen3_workflow_user
    description: Allows the creation of workflow tasks
    role_ids:
    - workflow_user
    resource_paths:
    - /services/workflow/gen3-workflow/tasks
  - id: gen3_workflow_admin
    description: Allows access to view tasks created by all users
    role_ids:
    - reader
    resource_paths:
    - /services/workflow/gen3-workflow/tasks

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
```
