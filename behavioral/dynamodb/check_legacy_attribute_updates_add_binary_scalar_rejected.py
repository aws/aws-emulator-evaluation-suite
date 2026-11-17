"""legacy-attribute-updates-add-binary-scalar-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "legacy-attribute-updates-add-binary-scalar-rejected"
GROUP = "update-expression"
SERVICES = ["dynamodb"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _wait_active(ddb, table, timeout_s=40.0) -> None:
    """Poll DescribeTable until the table is ACTIVE; on expiry fail with the last status read."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = ddb.describe_table(TableName=table)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"table {table} not ACTIVE within {timeout_s:.0f}s; last TableStatus {status!r}")
        time.sleep(1.0)


def _error(fn):
    """The ClientError ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


_ADD_ON_B_REJECTED = (
    "ValidationException",
    "1 validation error detected: One or more parameter values were invalid: "
    "ADD action is not supported for the type B",
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Legacy AttributeUpdates ADD on a Binary (B) scalar attribute is refused, leaving the item
    unchanged, while the same Action on a Binary Set (BS) attribute still applies.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-addb-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, table)

    key = {"pk": {"S": "item1"}}
    ddb.put_item(TableName=table, Item={
        **key,
        "blob": {"B": b"x"},
        "blobs": {"BS": [b"a"]},
    })

    exc = _error(lambda: ddb.update_item(
        TableName=table, Key=key,
        AttributeUpdates={"blob": {"Action": "ADD", "Value": {"B": b"y"}}},
    ))
    code, msg = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    assert (code, msg) == _ADD_ON_B_REJECTED, (
        f"ADD onto a Binary (B) attribute: expected {_ADD_ON_B_REJECTED!r}, got {(code, msg)!r}"
    )

    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert unchanged is not None and unchanged.get("blob") == {"B": b"x"}, (
        f"'blob' changed by the rejected ADD: {unchanged.get('blob')!r}, expected b'x' unchanged"
    )

    new_blobs = ddb.update_item(
        TableName=table, Key=key,
        AttributeUpdates={"blobs": {"Action": "ADD", "Value": {"BS": [b"z"]}}},
        ReturnValues="UPDATED_NEW",
    ).get("Attributes")
    assert new_blobs is not None and set(new_blobs["blobs"]["BS"]) == {b"a", b"z"}, (
        f"positive control: ADD BS {{z}} onto existing {{a}} with UPDATED_NEW returned {new_blobs!r}, "
        f"expected the union {{a,z}}"
    )

    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert item is not None and set(item["blobs"]["BS"]) == {b"a", b"z"}, (
        f"final blobs read back as {item.get('blobs')!r}, expected {{a,z}} after the positive control"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
