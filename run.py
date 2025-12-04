"""
Usage:
- Run app: python run.py
- Generate openapi docs: python run.py openapi
"""

import os
import sys

import uvicorn
import yaml

from gen3workflow.app import get_app


CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))


if __name__ == "__main__":
    if sys.argv[-1] == "openapi":  # generate openapi docs
        app = get_app()
        schema = app.openapi()
        path = os.path.join(CURRENT_DIR, "docs/openapi.yaml")
        yaml.Dumper.ignore_aliases = lambda *args: True
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w+") as f:
            yaml.dump(schema, f, default_flow_style=False)
        print(f"Saved docs at {path}")
    else:
        host = "0.0.0.0"
        port = 8080
        print(f"gen3workflow.app:app running at {host}:{port}")
        uvicorn.run("gen3workflow.app:app", host=host, port=port, reload=True)
