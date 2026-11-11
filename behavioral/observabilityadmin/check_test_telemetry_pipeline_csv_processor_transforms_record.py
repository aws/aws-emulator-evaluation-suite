"""test-telemetry-pipeline-csv-processor-transforms-record."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "test-telemetry-pipeline-csv-processor-transforms-record"
GROUP = "data-plane"
SERVICES = ["observabilityadmin"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestTelemetryPipeline runs a csv processor on a STRING record "red,green" and returns one JSON
    record {"column_1": "red", "column_2": "green"}, not the input echoed back."""
    client = ctx.client("observabilityadmin")
    config = {"Body": "pipeline:\n  processor:\n    - csv: {}\n"}

    resp = client.test_telemetry_pipeline(
        Configuration=config,
        Records=[{"Data": "red,green", "Type": "STRING"}],
        SignalType="LOG",
    )

    results = resp["Results"]
    assert len(results) == 1, f"expected 1 result, got {len(results)}: {results!r}"
    record = results[0]["Record"]
    assert record["Type"] == "JSON", f"expected Type=JSON after csv processor, got {record['Type']!r}"
    payload = json.loads(record["Data"])
    assert payload == {"column_1": "red", "column_2": "green"}, (
        f"expected csv processor to split 'red,green' into column_1/column_2, got {payload!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
