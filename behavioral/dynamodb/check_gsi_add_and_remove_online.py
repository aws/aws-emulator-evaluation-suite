"""gsi-add-and-remove-online."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gsi-add-and-remove-online"
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


def _error_code_and_message(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to fail, but it succeeded")


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


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A GSI added to an ACTIVE table with UpdateTable becomes ACTIVE with its attribute definition and answers a
    Query; deleting it removes the index and its attribute definition, and a Query on it then raises
    ValidationException with the exact message.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=t, Item={"pk": {"S": "a"}, "gsi_pk": {"S": "grp"}})
    ddb.put_item(TableName=t, Item={"pk": {"S": "b"}})  # sparse: no gsi_pk

    ddb.update_table(
        TableName=t,
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "gsi_pk", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexUpdates=[
            {
                "Create": {
                    "IndexName": "late-gsi",
                    "KeySchema": [{"AttributeName": "gsi_pk", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "ALL"},
                }
            }
        ],
    )

    described_creating = ddb.describe_table(TableName=t)["Table"]
    gsis = {
        g["IndexName"]: g for g in described_creating.get("GlobalSecondaryIndexes", [])
    }
    assert "late-gsi" in gsis, gsis
    assert gsis["late-gsi"]["IndexStatus"] in ("CREATING", "ACTIVE"), gsis["late-gsi"]

    active_table = _wait_table_active(ddb, t, timeout_s=1800)
    active_gsi = next(
        g
        for g in active_table["GlobalSecondaryIndexes"]
        if g["IndexName"] == "late-gsi"
    )
    assert active_gsi["IndexStatus"] == "ACTIVE", active_gsi

    active_attr_names = {a["AttributeName"] for a in active_table["AttributeDefinitions"]}
    assert active_attr_names == {"pk", "gsi_pk"}, (
        f"expected AttributeDefinitions {{'pk', 'gsi_pk'}} with the index ACTIVE, "
        f"got {active_attr_names!r}"
    )

    resp = ddb.query(
        TableName=t,
        IndexName="late-gsi",
        KeyConditionExpression="gsi_pk = :g",
        ExpressionAttributeValues={":g": {"S": "grp"}},
    )
    assert resp["Count"] == 1, resp
    assert resp["Items"][0]["pk"] == {"S": "a"}, resp["Items"]

    # Now delete the GSI and confirm it fully disappears from DescribeTable.
    ddb.update_table(
        TableName=t, GlobalSecondaryIndexUpdates=[{"Delete": {"IndexName": "late-gsi"}}]
    )
    deleted_table = _poll_until(
        lambda: ddb.describe_table(TableName=t)["Table"],
        lambda tbl: (
            not any(
                g["IndexName"] == "late-gsi"
                for g in tbl.get("GlobalSecondaryIndexes", [])
            )
        ),
        timeout_s=150,
        interval_s=2.0,
        description="late-gsi removed from DescribeTable",
    )

    # Removing the index also removes the attribute definition it alone required: a
    # definition with no remaining key-schema reference does not linger.
    deleted_attr_names = {a["AttributeName"] for a in deleted_table["AttributeDefinitions"]}
    assert deleted_attr_names == {"pk"}, (
        f"expected AttributeDefinitions {{'pk'}} once late-gsi is gone, got {deleted_attr_names!r}"
    )

    # Gone must also mean unusable: a query against the now-deleted index must be refused,
    # not silently served (e.g. by falling back to a base-table scan).
    code, message = _error_code_and_message(
        lambda: ddb.query(
            TableName=t,
            IndexName="late-gsi",
            KeyConditionExpression="gsi_pk = :g",
            ExpressionAttributeValues={":g": {"S": "grp"}},
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException querying deleted index late-gsi, got {code!r}"
    )
    expected_message = "The table does not have the specified index: late-gsi"
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
