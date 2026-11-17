"""update-item-add-empty-number-and-binary-set-operand-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-add-empty-number-and-binary-set-operand-rejected"
GROUP = "negative-classes"
SERVICES = ["dynamodb"]
_EMPTY_NS = (
    "ValidationException",
    "1 validation error detected: One or more parameter values were invalid: "
    "An number set  may not be empty",
)
_EMPTY_BS = (
    "ValidationException",
    "1 validation error detected: One or more parameter values were invalid: "
    "Binary sets should not be empty",
)


def expect_error(fn, code: str, message: str) -> None:
    """Assert `fn()` raises a ClientError with exactly `(code, message)`; raises on success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        got = (err["Code"], err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem's ADD action rejects an empty number set and an empty binary set operand
    with AWS's exact per-type message, leaving the target attribute unchanged; a same-typed
    operand with a member still applies.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ns_key = {"pk": {"S": "ns"}}
    bs_key = {"pk": {"S": "bs"}}
    ddb.put_item(TableName=table, Item={**ns_key, "nums": {"NS": ["1"]}})
    ddb.put_item(TableName=table, Item={**bs_key, "blobs": {"BS": [b"a"]}})

    expect_error(lambda: ddb.update_item(
        TableName=table, Key=ns_key, UpdateExpression="ADD nums :e",
        ExpressionAttributeValues={":e": {"NS": []}},
    ), *_EMPTY_NS)

    expect_error(lambda: ddb.update_item(
        TableName=table, Key=bs_key, UpdateExpression="ADD blobs :e",
        ExpressionAttributeValues={":e": {"BS": []}},
    ), *_EMPTY_BS)

    unchanged_ns = ddb.get_item(TableName=table, Key=ns_key, ConsistentRead=True)["Item"]
    assert unchanged_ns["nums"]["NS"] == ["1"], (
        f"the rejected NS ADD must leave the attribute untouched, got {unchanged_ns['nums']!r}"
    )
    unchanged_bs = ddb.get_item(TableName=table, Key=bs_key, ConsistentRead=True)["Item"]
    assert unchanged_bs["blobs"]["BS"] == [b"a"], (
        f"the rejected BS ADD must leave the attribute untouched, got {unchanged_bs['blobs']!r}"
    )

    # Positive control: the same operand shape with a member applies, for both types.
    ddb.update_item(
        TableName=table, Key=ns_key, UpdateExpression="ADD nums :e",
        ExpressionAttributeValues={":e": {"NS": ["2"]}},
    )
    grown_ns = ddb.get_item(TableName=table, Key=ns_key, ConsistentRead=True)["Item"]
    assert set(grown_ns["nums"]["NS"]) == {"1", "2"}, (
        f"the positive-control NS ADD with a non-empty set must apply, got {grown_ns['nums']!r}"
    )

    ddb.update_item(
        TableName=table, Key=bs_key, UpdateExpression="ADD blobs :e",
        ExpressionAttributeValues={":e": {"BS": [b"b"]}},
    )
    grown_bs = ddb.get_item(TableName=table, Key=bs_key, ConsistentRead=True)["Item"]
    assert set(grown_bs["blobs"]["BS"]) == {b"a", b"b"}, (
        f"the positive-control BS ADD with a non-empty set must apply, got {grown_bs['blobs']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
