"""gsi-creating-blocks-other-index-but-accepts-self-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gsi-creating-blocks-other-index-but-accepts-self-delete"
GROUP = "gsi"
SERVICES = ["dynamodb"]

_N_ITEMS = 40


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn, what: str):
    """The Error dict a rejected call raises; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if not err:
            raise AssertionError(f"{what}: raised with no Error body: {exc!r}") from exc
        return err
    raise AssertionError(f"{what}: the call was ACCEPTED; real AWS rejects it: {result!r}")


def _delete_table_when_settled(ddb, table, timeout_s=600):
    deadline = time.time() + timeout_s

    def run_undo() -> None:
        while True:
            try:
                ddb.delete_table(TableName=table)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ResourceNotFoundException":
                    return
                if code != "ResourceInUseException" or time.time() > deadline:
                    raise
            time.sleep(2)

    return run_undo


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """While a GSI is still being created, UpdateTable adding a second, different GSI is
    refused with LimitExceededException, but deleting the GSI that is being built is accepted
    and the index disappears.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-gsilc-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_delete_table_when_settled(ddb, table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for i in range(_N_ITEMS):
        ddb.put_item(TableName=table, Item={"pk": {"S": f"item-{i:03d}"}, "g1": {"S": "grp"}})
    scanned = ddb.scan(TableName=table, Select="COUNT", ConsistentRead=True)["Count"]
    assert scanned == _N_ITEMS, f"expected {_N_ITEMS} items before adding the index, got {scanned}"

    add_resp = ddb.update_table(
        TableName=table,
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "g1", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexUpdates=[
            {
                "Create": {
                    "IndexName": "idx-a",
                    "KeySchema": [{"AttributeName": "g1", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "ALL"},
                }
            }
        ],
    )
    added = {g["IndexName"]: g for g in add_resp["TableDescription"].get("GlobalSecondaryIndexes", [])}
    assert set(added) == {"idx-a"}, f"UpdateTable described indexes {sorted(added)}, expected only idx-a"
    assert added["idx-a"]["IndexStatus"] == "CREATING", (
        f"a just-requested GSI must be CREATING, was {added['idx-a']['IndexStatus']!r}"
    )

    # Immediately: a second UpdateTable touching a DIFFERENT index while idx-a is still building.
    err = _error(
        lambda: ddb.update_table(
            TableName=table,
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "g1", "AttributeType": "S"},
                {"AttributeName": "g2", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexUpdates=[
                {
                    "Create": {
                        "IndexName": "idx-b",
                        "KeySchema": [{"AttributeName": "g2", "KeyType": "HASH"}],
                        "Projection": {"ProjectionType": "ALL"},
                    }
                }
            ],
        ),
        "UpdateTable adding idx-b while idx-a is building",
    )
    assert err.get("Code") == "LimitExceededException", (
        f"expected LimitExceededException, got {err.get('Code')!r} ({err.get('Message')!r})"
    )
    expected_msg = (
        "Subscriber limit exceeded: Only 1 online index can be created or deleted "
        "simultaneously per table"
    )
    assert err.get("Message") == expected_msg, (
        f"expected message {expected_msg!r}, got {err.get('Message')!r}"
    )
    after_refusal = ddb.describe_table(TableName=table)["Table"]
    names_after_refusal = sorted(g["IndexName"] for g in after_refusal.get("GlobalSecondaryIndexes", []))
    assert names_after_refusal == ["idx-a"], (
        f"a refused add must leave the index set unchanged, got {names_after_refusal!r}"
    )

    # Immediately: a second UpdateTable deleting the SAME index that is still building. Accepted.
    delete_resp = ddb.update_table(
        TableName=table,
        GlobalSecondaryIndexUpdates=[{"Delete": {"IndexName": "idx-a"}}],
    )
    deleted = {
        g["IndexName"]: g
        for g in delete_resp["TableDescription"].get("GlobalSecondaryIndexes", [])
    }
    assert set(deleted) == {"idx-a"}, (
        f"UpdateTable self-delete described indexes {sorted(deleted)}, expected only idx-a"
    )
    assert deleted["idx-a"]["IndexStatus"] == "DELETING", (
        f"a just-accepted self-delete must report idx-a DELETING, got "
        f"{deleted['idx-a']['IndexStatus']!r}"
    )

    deadline = time.time() + 600
    final = None
    while time.time() < deadline:
        tbl = ddb.describe_table(TableName=table)["Table"]
        gsis = tbl.get("GlobalSecondaryIndexes", [])
        if not gsis and tbl["TableStatus"] == "ACTIVE":
            final = tbl
            break
        time.sleep(2)
    assert final is not None, (
        f"idx-a was never fully removed within 600s; last seen "
        f"{ddb.describe_table(TableName=table)['Table'].get('GlobalSecondaryIndexes')!r}"
    )
    attr_names = {a["AttributeName"] for a in final["AttributeDefinitions"]}
    assert attr_names == {"pk"}, (
        f"removing idx-a must also drop the attribute definition it alone needed, got {attr_names!r}"
    )

    code_after = _error(
        lambda: ddb.query(
            TableName=table,
            IndexName="idx-a",
            KeyConditionExpression="g1 = :g",
            ExpressionAttributeValues={":g": {"S": "grp"}},
        ),
        "Query against the now-deleted idx-a",
    )
    assert code_after.get("Code") == "ValidationException", (
        f"expected ValidationException querying deleted idx-a, got {code_after.get('Code')!r}"
    )
    expected_query_msg = "The table does not have the specified index: idx-a"
    assert code_after.get("Message") == expected_query_msg, (
        f"expected message {expected_query_msg!r}, got {code_after.get('Message')!r}"
    )

    scanned_after = ddb.scan(TableName=table, Select="COUNT", ConsistentRead=True)["Count"]
    assert scanned_after == _N_ITEMS, (
        f"the base table lost items across the index lifecycle: expected {_N_ITEMS}, got {scanned_after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
