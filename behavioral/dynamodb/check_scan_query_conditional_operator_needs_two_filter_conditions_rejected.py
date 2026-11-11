"""scan-query-conditional-operator-needs-two-filter-conditions-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-query-conditional-operator-needs-two-filter-conditions-rejected"
GROUP = "query"
SERVICES = ["dynamodb"]

_WITHOUT_FILTER_MSG = "ConditionalOperator cannot be used without Filter or Expected"
_TWO_OR_MORE_MSG = "ConditionalOperator can only be used when Filter or Expected has two or more elements"


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
    """ConditionalOperator with an empty ScanFilter, only AttributesToGet, no key condition, or a
    one-condition ScanFilter/QueryFilter is ValidationException; a two-condition filter is accepted.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/LegacyConditionalParameters.ConditionalOperator.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-condop-read-")
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

    cases = [
        ("Scan with ConditionalOperator and ScanFilter {}", _WITHOUT_FILTER_MSG,
         lambda: ddb.scan(TableName=table, ConditionalOperator="AND", ScanFilter={})),
        ("Scan with ConditionalOperator and only AttributesToGet", _WITHOUT_FILTER_MSG,
         lambda: ddb.scan(TableName=table, ConditionalOperator="AND", AttributesToGet=["a", "b"])),
        ("Scan with ConditionalOperator and a one-condition ScanFilter", _TWO_OR_MORE_MSG,
         lambda: ddb.scan(TableName=table, ConditionalOperator="AND", ScanFilter={"a": _cond("x")})),
        ("Query with ConditionalOperator and no key condition", _WITHOUT_FILTER_MSG,
         lambda: ddb.query(TableName=table, ConditionalOperator="AND")),
        ("Query with ConditionalOperator and a one-condition QueryFilter", _TWO_OR_MORE_MSG,
         lambda: ddb.query(TableName=table, ConditionalOperator="AND",
                           KeyConditions={"pk": _cond("k1")}, QueryFilter={"a": _cond("x")})),
    ]
    for label, want, fn in cases:
        code, msg = _error(fn)
        assert (code, msg) == ("ValidationException", want), f"{label} gave {code!r}: {msg!r}"

    scan = ddb.scan(TableName=table, ConditionalOperator="AND", ConsistentRead=True,
                    ScanFilter={"a": _cond("x"), "b": _cond("y")})
    assert scan["Items"] == [item], f"Scan with a two-condition AND ScanFilter returned {scan['Items']!r}"
    query = ddb.query(TableName=table, ConditionalOperator="OR", ConsistentRead=True,
                      KeyConditions={"pk": _cond("k1")},
                      QueryFilter={"a": _cond("x"), "b": _cond("nope")})
    assert query["Items"] == [item], f"Query with a two-condition OR QueryFilter returned {query['Items']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
