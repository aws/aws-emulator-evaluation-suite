"""all-projected-attributes-select-serves-include-index-projection."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "all-projected-attributes-select-serves-include-index-projection"
GROUP = "gsi"
SERVICES = ["dynamodb"]

_LSI = "include-lsi"
_GSI = "include-gsi"


def _poll_count(fn, want, *, timeout_s=120.0, interval_s=2.0):
    """*fn*'s result once its Count reaches *want*; a GSI write is eventually consistent."""
    deadline = time.monotonic() + timeout_s
    result = fn()
    while result.get("Count", 0) != want:
        if time.monotonic() >= deadline:
            raise AssertionError(f"Count never reached {want} within {timeout_s}s: {result!r}")
        time.sleep(interval_s)
        result = fn()
    return result


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Select=ALL_PROJECTED_ATTRIBUTES returns the table key, the index's own key and the index's
    NonKeyAttributes, and nothing else, on Query and Scan of an INCLUDE LSI and on Query of an
    INCLUDE GSI.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbproj-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                   {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": n, "AttributeType": "S"}
                              for n in ("pk", "sk", "li", "gi")],
        BillingMode="PAY_PER_REQUEST",
        LocalSecondaryIndexes=[{
            "IndexName": _LSI,
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"},
                          {"AttributeName": "li", "KeyType": "RANGE"}],
            "Projection": {"ProjectionType": "INCLUDE", "NonKeyAttributes": ["kept_l"]},
        }],
        GlobalSecondaryIndexes=[{
            "IndexName": _GSI,
            "KeySchema": [{"AttributeName": "gi", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "INCLUDE", "NonKeyAttributes": ["kept_g"]},
        }],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=table, Item={
        "pk": {"S": "p"}, "sk": {"S": "s"}, "li": {"S": "l"}, "gi": {"S": "g"},
        "kept_l": {"S": "KL"}, "kept_g": {"S": "KG"}, "excluded": {"S": "X"},
    })
    base = ddb.get_item(TableName=table, Key={"pk": {"S": "p"}, "sk": {"S": "s"}},
                        ConsistentRead=True)["Item"]
    assert base.get("excluded") == {"S": "X"}, (
        f"the base item must really carry 'excluded', or the absences asserted below are vacuous: "
        f"{base!r}"
    )

    # --- Query, INCLUDE LSI: the LSI shares the base table's partition, so a consistent read
    # needs no propagation wait. ---
    lsi_query = ddb.query(TableName=table, IndexName=_LSI, KeyConditionExpression="pk = :p",
                         ExpressionAttributeValues={":p": {"S": "p"}},
                         Select="ALL_PROJECTED_ATTRIBUTES", ConsistentRead=True)["Items"][0]
    assert sorted(lsi_query) == ["kept_l", "li", "pk", "sk"], (
        f"Query Select=ALL_PROJECTED_ATTRIBUTES on an INCLUDE LSI must return the table key, the "
        f"index's own key and its NonKeyAttributes and nothing else, got {sorted(lsi_query)!r}"
    )
    assert lsi_query.get("kept_l") == {"S": "KL"}, (
        f"the INCLUDEd attribute must be served with its value, got {lsi_query.get('kept_l')!r}"
    )
    assert "excluded" not in lsi_query, (
        f"an attribute outside the INCLUDE list must not be served, got {lsi_query!r}"
    )

    # --- Scan, INCLUDE LSI: same projection rule, the other operation. ---
    lsi_scan = ddb.scan(TableName=table, IndexName=_LSI, Select="ALL_PROJECTED_ATTRIBUTES",
                       ConsistentRead=True)["Items"][0]
    assert sorted(lsi_scan) == ["kept_l", "li", "pk", "sk"], (
        f"Scan Select=ALL_PROJECTED_ATTRIBUTES on an INCLUDE LSI must return the table key, the "
        f"index's own key and its NonKeyAttributes and nothing else, got {sorted(lsi_scan)!r}"
    )
    assert lsi_scan.get("kept_l") == {"S": "KL"}, (
        f"the INCLUDEd attribute must be served with its value, got {lsi_scan.get('kept_l')!r}"
    )
    assert "excluded" not in lsi_scan, (
        f"an attribute outside the INCLUDE list must not be served, got {lsi_scan!r}"
    )

    # --- Query, INCLUDE GSI: eventually consistent, so poll until the write propagates. ---
    gsi_resp = _poll_count(
        lambda: ddb.query(TableName=table, IndexName=_GSI, KeyConditionExpression="gi = :g",
                          ExpressionAttributeValues={":g": {"S": "g"}},
                          Select="ALL_PROJECTED_ATTRIBUTES"),
        1,
    )
    gsi_item = gsi_resp["Items"][0]
    assert sorted(gsi_item) == ["gi", "kept_g", "pk", "sk"], (
        f"Query Select=ALL_PROJECTED_ATTRIBUTES on an INCLUDE GSI must return the table key, the "
        f"index's own key and its NonKeyAttributes and nothing else, got {sorted(gsi_item)!r}"
    )
    assert gsi_item.get("kept_g") == {"S": "KG"}, (
        f"the INCLUDEd attribute must be served with its value, got {gsi_item.get('kept_g')!r}"
    )
    assert "excluded" not in gsi_item, (
        f"an attribute outside the INCLUDE list must not be served, got {gsi_item!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
