"""get-item-missing-range-key-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-item-missing-range-key-rejected"
GROUP = 'overly-permissive'
SERVICES = ['dynamodb']


def _error_code_and_message(fn):
    """Call fn(); return the botocore Error.Code and Error.Message if a ClientError is raised. An
    unexpected SUCCESS raises, because an emulator ACCEPTING input real AWS refuses is the strongest
    signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _wait_table_active(ddb, table_name, timeout_s=60.0, interval_s=1.0):
    """Poll DescribeTable until TableStatus is ACTIVE (a transient 404 counts as not-yet)."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            status = "PENDING"
        if status == "ACTIVE":
            return status
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never went ACTIVE in {timeout_s}s (last={status})")


def _create_table_and_wait(ddb, ctx, table_name, key_schema, attribute_definitions,
                           billing_mode="PAY_PER_REQUEST", timeout_s=60.0, **kwargs):
    """Create a table, register teardown, and wait until ACTIVE."""
    resp = ddb.create_table(
        TableName=table_name,
        KeySchema=key_schema,
        AttributeDefinitions=attribute_definitions,
        BillingMode=billing_mode,
        **kwargs,
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_table_active(ddb, table_name, timeout_s=timeout_s)
    return resp


def _composite_key_schema(hash_name="pk", range_name="sk", hash_type="S", range_type="S"):
    """Return (KeySchema, AttributeDefinitions) for a hash+range table."""
    return (
        [
            {"AttributeName": hash_name, "KeyType": "HASH"},
            {"AttributeName": range_name, "KeyType": "RANGE"},
        ],
        [
            {"AttributeName": hash_name, "AttributeType": hash_type},
            {"AttributeName": range_name, "AttributeType": range_type},
        ],
    )


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetItem on a hash+range table supplying only the hash key must be rejected, not resolved to some item."""
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-ddb-partialkey-")
    key_schema, attr_defs = _composite_key_schema("pk", "sk")
    _create_table_and_wait(
        ddb, ctx, table_name, key_schema, attr_defs,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    ddb.put_item(TableName=table_name, Item={"pk": {"S": "p1"}, "sk": {"S": "s1"}})

    code, message = _error_code_and_message(
        lambda: ddb.get_item(TableName=table_name, Key={"pk": {"S": "p1"}}, ConsistentRead=True)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = "The provided key element does not match the schema"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # A fully-specified key must still work, proving the table itself is healthy.
    ok = ddb.get_item(
        TableName=table_name, Key={"pk": {"S": "p1"}, "sk": {"S": "s1"}}, ConsistentRead=True
    )
    assert "Item" in ok, f"expected Item in response for a fully-specified key, got {ok!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
