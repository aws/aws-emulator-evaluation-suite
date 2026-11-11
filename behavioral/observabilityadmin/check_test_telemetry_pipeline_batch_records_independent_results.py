"""test-telemetry-pipeline-batch-records-independent-results."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "test-telemetry-pipeline-batch-records-independent-results"
GROUP = "data-plane"
SERVICES = ["observabilityadmin"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestTelemetryPipeline with a csv processor parses two STRING records of 2 and 3 columns into
    their own JSON column_N objects, in input order."""
    client = ctx.client("observabilityadmin")
    config = {"Body": "pipeline:\n  processor:\n    - csv: {}\n"}

    resp = client.test_telemetry_pipeline(
        Configuration=config,
        Records=[
            {"Data": "red,green", "Type": "STRING"},
            {"Data": "a,b,c", "Type": "STRING"},
        ],
        SignalType="LOG",
    )

    results = resp["Results"]
    assert len(results) == 2, f"expected 2 Results for 2 input records, got {len(results)}"

    first_record = results[0]["Record"]
    second_record = results[1]["Record"]
    assert first_record["Type"] == "JSON", f"expected Results[0].Record.Type == JSON, got {first_record['Type']!r}"
    assert second_record["Type"] == "JSON", f"expected Results[1].Record.Type == JSON, got {second_record['Type']!r}"

    first = json.loads(first_record["Data"])
    second = json.loads(second_record["Data"])
    assert first == {"column_1": "red", "column_2": "green"}, (
        f"expected Results[0] shaped from 'red,green', got {first!r}"
    )
    assert second == {"column_1": "a", "column_2": "b", "column_3": "c"}, (
        f"expected Results[1] shaped from 'a,b,c' with its own column count, got {second!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
