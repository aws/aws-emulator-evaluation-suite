"""scan-query-legacy-and-expression-mixing-names-every-parameter-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-query-legacy-and-expression-mixing-names-every-parameter-rejected"
GROUP = "query"
SERVICES = ["dynamodb"]

_MIXING_MSG = (
    "Can not use both expression and non-expression parameters in the same request: "
    "Non-expression parameters: {{{legacy}}} Expression parameters: {{{expr}}}"
)


def _cond(value):
    """A legacy EQ condition on one string value."""
    return {"ComparisonOperator": "EQ", "AttributeValueList": [{"S": value}]}


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


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Scan or Query mixing legacy and expression parameters is ValidationException listing every
    one present per side in AWS's order, ahead of an unused value; KeyConditions + filter is fine.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/LegacyConditionalParameters.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-mixing-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)
    item = {"pk": {"S": "k1"}, "a": {"S": "x"}, "b": {"S": "y"}}
    ddb.put_item(TableName=table, Item=item)
    v = {":v": {"S": "x"}}
    p = {":p": {"S": "k1"}}

    cases = [
        ("ConditionalOperator", "ProjectionExpression", "Scan ConditionalOperator + ProjectionExpression",
         lambda: ddb.scan(TableName=table, ConditionalOperator="AND", ProjectionExpression="a")),
        ("ConditionalOperator", "KeyConditionExpression",
         "Query ConditionalOperator + KeyConditionExpression",
         lambda: ddb.query(TableName=table, ConditionalOperator="AND",
                           KeyConditionExpression="pk = :p", ExpressionAttributeValues=p)),
        ("AttributesToGet, ScanFilter, ConditionalOperator", "ProjectionExpression, FilterExpression",
         "Scan with every legacy and expression parameter",
         lambda: ddb.scan(TableName=table, AttributesToGet=["a"], ScanFilter={"a": _cond("x")},
                          ConditionalOperator="AND", FilterExpression="a = :v",
                          ProjectionExpression="b", ExpressionAttributeValues=v)),
        ("QueryFilter, ConditionalOperator, KeyConditions",
         "ProjectionExpression, FilterExpression, KeyConditionExpression",
         "Query with every legacy and expression parameter",
         lambda: ddb.query(TableName=table, KeyConditions={"pk": _cond("k1")},
                           QueryFilter={"a": _cond("x")}, ConditionalOperator="AND",
                           KeyConditionExpression="pk = :p", FilterExpression="a = :v",
                           ProjectionExpression="b", ExpressionAttributeValues={**p, **v})),
        ("ConditionalOperator", "FilterExpression",
         "Scan ConditionalOperator + FilterExpression with an unused value",
         lambda: ddb.scan(TableName=table, ConditionalOperator="AND", FilterExpression="a = :v",
                          ExpressionAttributeValues={**v, ":unused": {"S": "y"}})),
        ("ScanFilter", "ProjectionExpression", "Scan ScanFilter + ProjectionExpression",
         lambda: ddb.scan(TableName=table, ScanFilter={"a": _cond("x")}, ProjectionExpression="b")),
        ("AttributesToGet", "KeyConditionExpression", "Query AttributesToGet + KeyConditionExpression",
         lambda: ddb.query(TableName=table, AttributesToGet=["a"],
                           KeyConditionExpression="pk = :p", ExpressionAttributeValues=p)),
        ("QueryFilter", "FilterExpression, KeyConditionExpression",
         "Query QueryFilter + FilterExpression + KeyConditionExpression",
         lambda: ddb.query(TableName=table, QueryFilter={"a": _cond("x")},
                           KeyConditionExpression="pk = :p", FilterExpression="a = :v",
                           ExpressionAttributeValues={**p, **v})),
        ("QueryFilter", "FilterExpression",
         "Query KeyConditions + QueryFilter + FilterExpression",
         lambda: ddb.query(TableName=table, KeyConditions={"pk": _cond("k1")},
                           QueryFilter={"a": _cond("x")}, FilterExpression="a = :v",
                           ExpressionAttributeValues=v)),
    ]
    for legacy, expr, label, fn in cases:
        want = _MIXING_MSG.format(legacy=legacy, expr=expr)
        code, msg = _error(fn)
        assert (code, msg) == ("ValidationException", want), f"{label} gave {code!r}: {msg!r}"

    query = ddb.query(TableName=table, KeyConditions={"pk": _cond("k1")}, FilterExpression="a = :v",
                      ExpressionAttributeValues=v, ConsistentRead=True)
    assert query["Items"] == [item], f"Query KeyConditions + FilterExpression returned {query['Items']!r}"
    query = ddb.query(TableName=table, KeyConditions={"pk": _cond("k1")}, ProjectionExpression="a",
                      ConsistentRead=True)
    assert query["Items"] == [{"a": {"S": "x"}}], (
        f"Query KeyConditions + ProjectionExpression returned {query['Items']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
