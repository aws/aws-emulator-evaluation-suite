"""fleet-index-aggregation-queries-consistent."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "fleet-index-aggregation-queries-consistent"
GROUP = "server-side"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """Over 5 indexed things, GetStatistics reports count 5, min 10 and max 50,
    GetCardinality of a shared value is 1, and GetPercentiles 0 and 100 lie within that min
    and max."""
    iot = ctx.client("iot")

    original = iot.get_indexing_configuration().get("thingIndexingConfiguration", {})
    original_mode = original.get("thingIndexingMode", "OFF")
    original_custom_fields = original.get("customFields", [])

    def _restore():
        iot.update_indexing_configuration(
            thingIndexingConfiguration={
                "thingIndexingMode": original_mode,
                "customFields": original_custom_fields,
            }
        )

    ctx.on_cleanup(_restore)

    # Aggregation queries (GetCardinality/GetPercentiles/GetStatistics with a field) only work
    # on AWS managed fields or attributes explicitly registered as custom fields.
    iot.update_indexing_configuration(
        thingIndexingConfiguration={
            "thingIndexingMode": "REGISTRY",
            "customFields": [
                {"name": "attributes.fixture", "type": "String"},
                {"name": "attributes.battery", "type": "Number"},
            ],
        }
    )
    _poll_until(
        lambda: iot.describe_index(indexName="AWS_Things")["indexStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=60.0,
    )

    fixture = ctx.unique_name("sim2real-iot-fixture-")
    battery_levels = [10, 20, 30, 40, 50]
    thing_names = [ctx.unique_name(f"sim2real-iot-fxthing-{i}-") for i in range(5)]
    for name, level in zip(thing_names, battery_levels):
        iot.create_thing(
            thingName=name,
            attributePayload={"attributes": {"fixture": fixture, "battery": str(level)}},
        )
        ctx.on_cleanup(lambda n=name: iot.delete_thing(thingName=n))

    query = f'attributes.fixture:"{fixture}"'

    stats = _poll_until(
        lambda: iot.get_statistics(queryString=query, aggregationField="attributes.battery")[
            "statistics"
        ],
        lambda s: s.get("count") == len(thing_names),
        timeout_s=120.0,
        interval_s=5.0,
    )
    count = stats["count"]
    assert count == 5, f"expected 5 matched things, got count={count}"
    assert stats["minimum"] == 10.0, f"expected minimum battery 10.0, got {stats['minimum']}"
    assert stats["maximum"] == 50.0, f"expected maximum battery 50.0, got {stats['maximum']}"

    cardinality = iot.get_cardinality(queryString=query, aggregationField="attributes.fixture")[
        "cardinality"
    ]
    assert cardinality == 1, f"expected a single distinct fixture value, got cardinality={cardinality}"
    assert cardinality <= count, "cardinality must never exceed the matched document count"

    percentiles = iot.get_percentiles(
        queryString=query, aggregationField="attributes.battery", percents=[0.0, 100.0]
    )["percentiles"]
    assert len(percentiles) == 2, f"expected 2 percentile entries (0th, 100th), got {len(percentiles)}"
    by_percent = {p["percent"]: p["value"] for p in percentiles}
    assert by_percent[0.0] >= stats["minimum"] - 1e-6, "0th percentile must not be below the minimum"
    assert by_percent[100.0] <= stats["maximum"] + 1e-6, "100th percentile must not exceed the maximum"
    assert by_percent[0.0] <= by_percent[100.0], "percentiles must be non-decreasing"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
