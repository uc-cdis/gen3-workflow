"""
Usage:
- Run app: python run.py
- Generate openapi docs: python run.py openapi
"""

import os
import sys

from fastapi.routing import APIRoute
import uvicorn
import yaml

from gen3workflow.app import get_app


CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))


def overwrite_openapi_operation_ids(app) -> None:
    """
    The default operation ID format is `<function name>_<full route>_<method>`.
    A bug is causing the operation IDs for the `/s3` endpoint, which accepts all methods, to not
    be generated properly. This ensures unique operation IDs are generated for all routes.
    """
    existing_routes = set()
    for route in app.routes:
        if not isinstance(route, APIRoute) or not route.include_in_schema:
            continue
        route.operation_id = route.name
        i = 2
        while route.operation_id in existing_routes:
            route.operation_id = f"{route.name}_{i}"
            i += 1
        existing_routes.add(route.operation_id)


if __name__ == "__main__":
    if sys.argv[-1] == "openapi":  # generate openapi docs
        app = get_app()
        overwrite_openapi_operation_ids(app)
        schema = app.openapi()
        path = os.path.join(CURRENT_DIR, "docs/openapi.yaml")
        yaml.Dumper.ignore_aliases = lambda *args: True
        with open(path, "w+") as f:
            yaml.dump(schema, f, default_flow_style=False)
        print(f"Saved docs at {path}")
    else:
        host = "0.0.0.0"
        port = 8080
        print(f"gen3workflow.app:app running at {host}:{port}")
        uvicorn.run("gen3workflow.app:app", host=host, port=port, reload=True)
