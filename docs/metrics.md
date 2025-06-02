## Metrics

Metrics can be exposed at a `/metrics` endpoint compatible with Prometheus scraping and visualized in Prometheus or
Graphana, etc.

The metrics are defined in `gen3workflow/metrics.py` as follows:

* **gen3_workflow_api_requests_total**:  API requests for made to Gen3-Workflow service.
* ** **More metrics yet to be decided** **

You can [run Prometheus locally](https://github.com/prometheus/prometheus) if you want to test or visualize these.
