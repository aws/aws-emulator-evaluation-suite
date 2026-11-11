"""data-plane-fleet-indexing-aggregation-reflects-thing-state."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "data-plane-fleet-indexing-aggregation-reflects-thing-state"
GROUP = "server-side"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """With fleet indexing enabled, GetCardinality/GetBucketsAggregation/GetStatistics reflect
    the actual set of registered things -- not a static or permanently empty result."""
    iot = ctx.client("iot")

    original = iot.get_indexing_configuration()
    original_thing_cfg = original.get("thingIndexingConfiguration", {"thingIndexingMode": "OFF"})
    ctx.on_cleanup(lambda: iot.update_indexing_configuration(thingIndexingConfiguration=original_thing_cfg))
    iot.update_indexing_configuration(
        thingIndexingConfiguration={
            "thingIndexingMode": "REGISTRY",
            "customFields": [
                {"name": "attributes.fibatch", "type": "String"},
                {"name": "attributes.finum", "type": "Number"},
            ],
        }
    )

    batch_id = ctx.unique_name("s2rfibatch")[-24:]
    numeric_values = [10.0, 20.0, 30.0]
    thing_names = [ctx.unique_name(f"sim2real-iot-fithing-{i}-") for i in range(3)]
    for name, num_value in zip(thing_names, numeric_values):
        iot.create_thing(
            thingName=name,
            attributePayload={"attributes": {"fibatch": batch_id, "finum": str(num_value)}},
        )
        ctx.on_cleanup(lambda n=name: iot.delete_thing(thingName=n))


    query = f"attributes.fibatch:{batch_id}"

    cardinality = _poll_until(
        lambda: iot.get_cardinality(queryString=query, aggregationField="thingName")["cardinality"],
        lambda v: v == 3,
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert cardinality == 3, f"expected cardinality 3 for the 3 fleet-tagged things, got {cardinality}"

    def _bucket_probe():
        resp = iot.get_buckets_aggregation(
            queryString=query,
            aggregationField="attributes.fibatch",
            bucketsAggregationType={"termsAggregation": {"maxBuckets": 10}},
        )
        matches = [b for b in resp["buckets"] if b["keyValue"] == batch_id]
        return resp["totalCount"], matches

    total_count, matches = _poll_until(
        _bucket_probe,
        lambda r: r[0] == 3 and len(r[1]) == 1 and r[1][0]["count"] == 3,
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert total_count == 3, f"expected 3 documents matched by fibatch query, got {total_count}"
    assert matches[0]["count"] == 3, f"expected the single fibatch bucket to hold all 3 things, got {matches[0]}"

    stats = _poll_until(
        lambda: iot.get_statistics(queryString=query, aggregationField="registry.version")["statistics"],
        lambda s: s.get("count") == 3,
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert stats["count"] == 3, f"expected registry.version stats over 3 things, got count={stats['count']}"
    assert stats["minimum"] == 1.0, f"freshly created things start at registry.version 1, got minimum={stats['minimum']}"
    assert stats["maximum"] == 1.0, f"no thing was updated, so registry.version must stay 1, got maximum={stats['maximum']}"

    percentiles = _poll_until(
        lambda: iot.get_percentiles(
            queryString=query, aggregationField="attributes.finum", percents=[0.0, 50.0, 100.0]
        )["percentiles"],
        lambda p: len(p) == 3,
        timeout_s=60.0,
        interval_s=5.0,
    )
    by_percent = {round(p["percent"]): p["value"] for p in percentiles}
    assert by_percent[0] == 10.0, f"0th percentile of finum must equal the created minimum 10.0, got {by_percent[0]}"
    assert by_percent[100] == 30.0, f"100th percentile of finum must equal the created maximum 30.0, got {by_percent[100]}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "IndexNotReadyException":
                raise
            time.sleep(interval_s)
            continue
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
