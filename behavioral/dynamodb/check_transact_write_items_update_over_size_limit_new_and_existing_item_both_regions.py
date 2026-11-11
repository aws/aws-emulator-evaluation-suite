"""transact-write-items-update-over-size-limit-new-and-existing-item-both-regions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-update-over-size-limit-new-and-existing-item-both-regions"
GROUP = "limits"
SERVICES = ["dynamodb"]
LIMIT_BYTES = 409600
_OVERSIZED_UPDATE = ("ValidationException", "Item size to update has exceeded the maximum allowed size")

# region-pinned: the claim is that AWS answers this one way in both of these Regions, so they
# are named directly rather than derived from the target.
_REGIONS = ("us-west-2", "us-east-1")


def expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn()`` is refused with exactly ``(code, message)``; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == code, f"expected {code!r}, got {err['Code']!r}: {err.get('Message')!r}"
        assert err["Message"] == message, f"expected message {message!r}, got {err['Message']!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _oversized_value(key: str) -> str:
    """A string value that puts the item exactly one byte over LIMIT_BYTES for ``pk``=key."""
    overhead = len(b"pk") + len(key.encode()) + len(b"data")
    return "g" * (LIMIT_BYTES + 1 - overhead)


def _wait_active(ddb, table_name: str, timeout_s: float = 120) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        status = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        assert time.monotonic() < deadline, f"table {table_name!r} still {status!r} after {timeout_s}s"
        time.sleep(2)


def _update(ddb, table_name: str, key: str, value: str):
    return ddb.transact_write_items(
        TransactItems=[
            {
                "Update": {
                    "TableName": table_name,
                    "Key": {"pk": {"S": key}},
                    "UpdateExpression": "SET #d = :v",
                    "ExpressionAttributeNames": {"#d": "data"},
                    "ExpressionAttributeValues": {":v": {"S": value}},
                }
            }
        ]
    )


def _probe_region(ddb, table_name: str) -> None:
    """Run the positive control, the existing-item grow and the fresh-item upsert in one region."""
    ddb.put_item(TableName=table_name, Item={"pk": {"S": "control"}, "data": {"S": "start"}})
    _update(ddb, table_name, "control", "grown-but-still-small")
    control_got = ddb.get_item(TableName=table_name, Key={"pk": {"S": "control"}}, ConsistentRead=True)
    assert control_got.get("Item", {}).get("data", {}).get("S") == "grown-but-still-small", (
        f"positive control TransactWriteItems Update failed, got {control_got.get('Item')!r}"
    )

    original = "o" * 1024
    ddb.put_item(TableName=table_name, Item={"pk": {"S": "existing"}, "data": {"S": original}})
    expect_error(lambda: _update(ddb, table_name, "existing", _oversized_value("existing")), *_OVERSIZED_UPDATE)
    existing_after = ddb.get_item(TableName=table_name, Key={"pk": {"S": "existing"}}, ConsistentRead=True)
    assert existing_after.get("Item", {}).get("data", {}).get("S") == original, (
        f"a refused TransactWriteItems Update must leave the existing item unchanged, "
        f"got {existing_after.get('Item')!r}"
    )

    expect_error(lambda: _update(ddb, table_name, "fresh", _oversized_value("fresh")), *_OVERSIZED_UPDATE)
    fresh_after = ddb.get_item(TableName=table_name, Key={"pk": {"S": "fresh"}}, ConsistentRead=True)
    assert "Item" not in fresh_after, (
        f"a refused TransactWriteItems Update on a key that never existed must not create it, "
        f"got {fresh_after.get('Item')!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems Update that would grow an item one byte past the 409600-byte size
    limit is refused as a top-level ValidationException, never a TransactionCanceledException,
    for an existing item and for a key that never existed, the same way in us-west-2 and us-east-1.
    """
    for region in _REGIONS:
        ddb = ctx.client("dynamodb", region=region)
        table_name = ctx.unique_name("sim2real-behav-ddbsz-")
        ddb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda ddb=ddb, table_name=table_name: ddb.delete_table(TableName=table_name))
        _wait_active(ddb, table_name)
        _probe_region(ddb, table_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
