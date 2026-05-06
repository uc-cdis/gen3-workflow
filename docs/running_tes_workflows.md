# Running TES Workflows with Gen3Workflow

## How commands work

When you submit a TES task, the `command` field specifies what runs inside the container. Your command runs in a shell, so you can use shell features like `&&`, `||`, pipes (`|`), and redirects (`>`).

The `command` field is an array — all elements are joined together to form the full command. The key rule is: **each element must be a single word or token with no spaces.**

---

## Supported command formats

### ✅ Full command as a single string

The simplest approach — write your entire command as one string in the first element:

```json
"command": ["cat /data/input.txt | wc -l && echo Done"]
```

### ✅ Each token as its own element

You can also split your command so that each word, flag, or argument is its own element. All elements are joined to form the final command:

```json
"command": ["echo", "hello,bird", "&&", "echo", "world"]
```

---

## What doesn't work

### ❌ Any element containing spaces (except when it is the only element)

```json
"command": ["echo Hello World!", "&&", "echo OHare"]
```

When an element contains spaces and there are other elements in the array, only the first element is executed — the rest are silently ignored. If you need spaces in your command, put the entire command in a single string, or use the script file approach (see below).

---

## Using a script file for complex commands

For commands that are too complex to write inline, you can upload a script to S3 and provide it as an input to your TES task. The script will be available inside the container at the path you specify, and you can invoke it directly in your `command`.

Upload your script to your S3 bucket, then reference it in your task definition:

```json
{
  "name": "Hello world with Word Count",
  "description": "Demonstrates the most basic echo task.",
  "inputs": [
    {
      "url": "s3://{{bucket_name}}/{{your_path}}/input.txt",
      "path": "/data/input.txt"
    }
  ],
  "outputs": [
    {
      "path": "/data/output.txt",
      "url": "s3://{{bucket_name}}/{{your_path}}/.output.txt",
      "type": "FILE"
    },
    {
      "path": "/data/grep_output.txt",
      "url": "s3://{{bucket_name}}/{{your_path}}/.grep_output.txt",
      "type": "FILE"
    }
  ],
  "executors": [
    {
      "image": "quay.io/nextflow/bash",
      "command": [
        "cat /data/input.txt > /data/.output.txt && grep hello /data/input.txt > /data/.grep_output.txt && echo 'Done!'"
      ]
    }
  ]
}
```

Your input files are available at the `path` you specify, and output files written to the `path` you define under `outputs` will be uploaded back to S3 when the task completes.

---

## File retention

Files stored in your workflow bucket are automatically deleted after **30 days**. Make sure to retrieve any output files before then.

> **Note for operators:** The retention period is configurable via the `S3_OBJECTS_EXPIRATION_DAYS` field in `gen3Config`.
