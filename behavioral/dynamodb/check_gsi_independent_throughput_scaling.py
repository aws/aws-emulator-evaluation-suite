"""gsi-independent-throughput-scaling."""

from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "gsi-independent-throughput-scaling"
GROUP = "gsi"
SERVICES = ["dynamodb"]


def _poll_until(
    probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _wait_table_active(ddb, name, timeout_s=90):
    return _poll_until(
        lambda: ddb.describe_table(TableName=name)["Table"],
        lambda t: (
            t["TableStatus"] == "ACTIVE"
            and all(
                idx.get("IndexStatus", "ACTIVE") == "ACTIVE"
                for idx in t.get("GlobalSecondaryIndexes", [])
            )
        ),
        timeout_s=timeout_s,
        interval_s=1.0,
        description=f"table {name} ACTIVE",
    )


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTable scaling a GSI's read capacity from 5 to 15 leaves the table at 5, and scaling the table to 20
    leaves the GSI at 15: the two throughputs change independently.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "gsi_pk", "AttributeType": "S"},
        ],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        GlobalSecondaryIndexes=[
            {
                "IndexName": "scaled-gsi",
                "KeySchema": [{"AttributeName": "gsi_pk", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {
                    "ReadCapacityUnits": 5,
                    "WriteCapacityUnits": 5,
                },
            }
        ],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    _wait_table_active(ddb, t, timeout_s=120)

    baseline = ddb.describe_table(TableName=t)["Table"]
    baseline_gsi = next(
        g for g in baseline["GlobalSecondaryIndexes"] if g["IndexName"] == "scaled-gsi"
    )
    assert baseline_gsi["ProvisionedThroughput"]["ReadCapacityUnits"] == 5, baseline_gsi
    assert baseline["ProvisionedThroughput"]["ReadCapacityUnits"] == 5, baseline

    # Scale ONLY the GSI's throughput up.
    ddb.update_table(
        TableName=t,
        GlobalSecondaryIndexUpdates=[
            {
                "Update": {
                    "IndexName": "scaled-gsi",
                    "ProvisionedThroughput": {
                        "ReadCapacityUnits": 15,
                        "WriteCapacityUnits": 15,
                    },
                }
            }
        ],
    )
    after_gsi_scale = _wait_table_active(ddb, t, timeout_s=180)
    gsi_after = next(
        g
        for g in after_gsi_scale["GlobalSecondaryIndexes"]
        if g["IndexName"] == "scaled-gsi"
    )
    assert gsi_after["ProvisionedThroughput"]["ReadCapacityUnits"] == 15, gsi_after
    assert after_gsi_scale["ProvisionedThroughput"]["ReadCapacityUnits"] == 5, (
        "scaling the GSI must not affect the base table's own throughput"
    )

    # Now scale ONLY the table's throughput up; the GSI's must be unaffected.
    ddb.update_table(
        TableName=t,
        ProvisionedThroughput={"ReadCapacityUnits": 20, "WriteCapacityUnits": 20},
    )
    after_table_scale = _wait_table_active(ddb, t, timeout_s=180)
    assert after_table_scale["ProvisionedThroughput"]["ReadCapacityUnits"] == 20, (
        after_table_scale
    )
    gsi_final = next(
        g
        for g in after_table_scale["GlobalSecondaryIndexes"]
        if g["IndexName"] == "scaled-gsi"
    )
    assert gsi_final["ProvisionedThroughput"]["ReadCapacityUnits"] == 15, (
        "scaling the base table must not affect the GSI's independently-set throughput"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
