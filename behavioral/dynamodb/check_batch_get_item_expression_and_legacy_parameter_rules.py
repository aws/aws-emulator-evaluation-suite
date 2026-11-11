"""batch-get-item-expression-and-legacy-parameter-rules."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-item-expression-and-legacy-parameter-rules"
GROUP = "batch"
SERVICES = ["dynamodb"]

_MIXED = (
    "Can not use both expression and non-expression parameters in the same request: "
    "Non-expression parameters: {AttributesToGet} Expression parameters: {ProjectionExpression}"
)
_NAMES_WITHOUT_EXPRESSION = "ExpressionAttributeNames can only be specified when using expressions"
_UNUSED_NAME = "Value provided in ExpressionAttributeNames unused in expressions: keys: {#n}"


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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetItem refuses ProjectionExpression with AttributesToGet on one table, names without a
    projection (also beside another table's AttributesToGet) and an unused name; legacy-only works.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_KeysAndAttributes.html
    """
    ddb = ctx.client("dynamodb")
    t1 = _create_table(ctx, ddb, "sim2real-behav-ddb-bgx-a-")
    t2 = _create_table(ctx, ddb, "sim2real-behav-ddb-bgx-b-")
    key = {"pk": {"S": "k1"}}
    ddb.put_item(TableName=t1, Item={**key, "a": {"S": "A"}, "b": {"S": "B"}})
    ddb.put_item(TableName=t2, Item={**key, "c": {"S": "C"}, "d": {"S": "D"}})

    refusals = {
        "ProjectionExpression with AttributesToGet on one table": (
            {t1: {"Keys": [key], "ProjectionExpression": "a", "AttributesToGet": ["a"]}}, _MIXED),
        "ExpressionAttributeNames without ProjectionExpression": (
            {t1: {"Keys": [key], "ExpressionAttributeNames": {"#n": "a"}}}, _NAMES_WITHOUT_EXPRESSION),
        "names without a projection beside another table's AttributesToGet": (
            {t1: {"Keys": [key], "ExpressionAttributeNames": {"#n": "a"}},
             t2: {"Keys": [key], "AttributesToGet": ["c"]}}, _NAMES_WITHOUT_EXPRESSION),
        "an ExpressionAttributeNames entry the projection does not use": (
            {t1: {"Keys": [key], "ProjectionExpression": "pk", "ExpressionAttributeNames": {"#n": "a"}}},
            _UNUSED_NAME),
    }
    for label, (request, expected) in refusals.items():
        code, msg = _error(lambda r=request: ddb.batch_get_item(RequestItems=r))
        assert (code, msg) == ("ValidationException", expected), f"BatchGetItem with {label} gave {code!r}: {msg!r}"

    legacy = ddb.batch_get_item(RequestItems={
        t1: {"Keys": [key], "AttributesToGet": ["a"], "ConsistentRead": True},
        t2: {"Keys": [key], "AttributesToGet": ["c"], "ConsistentRead": True},
    })
    assert legacy["Responses"] == {t1: [{"a": {"S": "A"}}], t2: [{"c": {"S": "C"}}]}, (
        f"AttributesToGet on both tables returned {legacy['Responses']!r}"
    )
    used = ddb.batch_get_item(RequestItems={
        t1: {"Keys": [key], "ProjectionExpression": "#n", "ExpressionAttributeNames": {"#n": "b"},
             "ConsistentRead": True},
    })
    assert used["Responses"] == {t1: [{"b": {"S": "B"}}]}, (
        f"a projection using its only name returned {used['Responses']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
