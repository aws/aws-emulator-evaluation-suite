"""batch-request-shape-defects-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-request-shape-defects-rejected"
GROUP = "batch"
SERVICES = ["dynamodb"]

_EMPTY_REQUEST_ITEMS = "The requestItems parameter is required for BatchWriteItem"
_BATCH_GET_EMPTY_REQUEST_ITEMS = (
    "1 validation error detected: Value at 'RequestItems' failed to satisfy constraint: "
    "Member must have length greater than or equal to 1"
)
_KEY_SCHEMA = "The provided key element does not match the schema"


def _teardown(undo, *not_found, timeout_s=300.0):
    """A cleanup running undo() where a failed delete raises; in-use is retried every 2 s."""
    def run_undo():
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                undo()
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code in not_found:
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)
    return run_undo


def _wait_active(ddb, ctx, table):
    """Poll DescribeTable every 2 s until the table and its indexes are ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE" and all(
            g.get("IndexStatus") == "ACTIVE" for g in desc.get("GlobalSecondaryIndexes", [])
        ):
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def _create_table(ctx, ddb, prefix, range_type=None):
    """Create an on-demand table keyed pk (S), plus sk of range_type when given; wait ACTIVE."""
    table = ctx.unique_name(prefix)
    keys = [{"AttributeName": "pk", "KeyType": "HASH"}]
    attrs = [{"AttributeName": "pk", "AttributeType": "S"}]
    if range_type:
        keys.append({"AttributeName": "sk", "KeyType": "RANGE"})
        attrs.append({"AttributeName": "sk", "AttributeType": range_type})
    ddb.create_table(
        TableName=table, KeySchema=keys, AttributeDefinitions=attrs, BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)
    return table


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises.

    An unexpected success fails, quoting the result.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _get(ddb, table, key):
    """The item at key read with ConsistentRead, or None."""
    return ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An empty RequestItems map, and a BatchGetItem or BatchWriteItem DeleteRequest key that is
    wrong-typed, missing its sort key or carries an extra attribute, are ValidationExceptions.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_BatchGetItem.html
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb, "sim2real-behav-ddb-bshape-", range_type="N")
    key = {"pk": {"S": "seed"}, "sk": {"N": "1"}}
    seed = {**key, "v": {"S": "kept"}}
    ddb.put_item(TableName=table, Item=seed)

    for label, want, call in [
        ("BatchGetItem", _BATCH_GET_EMPTY_REQUEST_ITEMS, lambda: ddb.batch_get_item(RequestItems={})),
        ("BatchWriteItem", _EMPTY_REQUEST_ITEMS, lambda: ddb.batch_write_item(RequestItems={})),
    ]:
        code, msg = _error(call)
        assert (code, msg) == ("ValidationException", want), (
            f"{label} with an empty RequestItems map gave {code!r}: {msg!r}"
        )

    bad_keys = {
        "a number-typed hash key": {"pk": {"N": "1"}, "sk": {"N": "1"}},
        "a missing sort key": {"pk": {"S": "seed"}},
        "an extra non-key attribute": {**key, "v": {"S": "kept"}},
    }
    for label, bad in bad_keys.items():
        code, msg = _error(lambda b=bad: ddb.batch_get_item(RequestItems={table: {"Keys": [key, b]}}))
        assert (code, msg) == ("ValidationException", _KEY_SCHEMA), (
            f"BatchGetItem with {label} gave {code!r}: {msg!r}"
        )

    extra = {**key, "v": {"S": "kept"}}
    code, msg = _error(lambda: ddb.batch_write_item(RequestItems={table: [
        {"DeleteRequest": {"Key": {"pk": {"S": "other"}, "sk": {"N": "2"}}}},
        {"DeleteRequest": {"Key": extra}},
    ]}))
    assert (code, msg) == ("ValidationException", _KEY_SCHEMA), (
        f"BatchWriteItem DeleteRequest with an extra key attribute gave {code!r}: {msg!r}"
    )
    got = _get(ddb, table, key)
    assert got == seed, f"the refused batch delete changed the seed to {got!r}"

    resp = ddb.batch_get_item(RequestItems={table: {"Keys": [key], "ConsistentRead": True}})
    assert resp["Responses"] == {table: [seed]}, f"a well-keyed BatchGetItem returned {resp['Responses']!r}"
    ddb.batch_write_item(RequestItems={table: [{"DeleteRequest": {"Key": key}}]})
    assert _get(ddb, table, key) is None, "a well-keyed batch DeleteRequest left the seed in place"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
