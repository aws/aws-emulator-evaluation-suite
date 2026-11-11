"""filter-and-key-condition-expression-size-limit-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "filter-and-key-condition-expression-size-limit-rejected"
GROUP = "validation"
SERVICES = ["dynamodb"]

_MAX = 4096
_FILTER_TOO_LONG_MSG = "Invalid FilterExpression: Expression size has exceeded the maximum allowed size;"
_KEY_CONDITION_TOO_LONG_MSG = (
    "Invalid KeyConditionExpression: Expression size has exceeded the maximum allowed size;"
)


def _path_of_len(total):
    """One attribute-name path of exactly `total` bytes."""
    return "a" + "z" * (total - 1)


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


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A FilterExpression (Scan, Query) or KeyConditionExpression over 4096 bytes is
    ValidationException; a 4096-byte FilterExpression is accepted.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-expr-size-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)
    item = {"pk": {"S": "k1"}, "foo": {"S": "a"}}
    ddb.put_item(TableName=table, Item=item)
    suffix = " = :v"
    over_filter = _path_of_len(_MAX + 1 - len(suffix)) + suffix
    at_filter = _path_of_len(_MAX - len(suffix)) + suffix
    over_key = "pk = :p AND " + _path_of_len(_MAX + 1 - len("pk = :p AND  = :q")) + " = :q"
    assert (len(over_filter), len(at_filter), len(over_key)) == (_MAX + 1, _MAX, _MAX + 1), (
        f"expression lengths {len(over_filter)!r}, {len(at_filter)!r}, {len(over_key)!r}"
    )
    v = {":v": {"S": "x"}}
    p = {":p": {"S": "k1"}}

    cases = [
        ("Scan with a 4097-byte FilterExpression", _FILTER_TOO_LONG_MSG,
         lambda: ddb.scan(TableName=table, FilterExpression=over_filter, ExpressionAttributeValues=v)),
        ("Query with a 4097-byte FilterExpression", _FILTER_TOO_LONG_MSG,
         lambda: ddb.query(TableName=table, KeyConditionExpression="pk = :p",
                           FilterExpression=over_filter, ExpressionAttributeValues={**p, **v})),
        ("Query with a 4097-byte KeyConditionExpression", _KEY_CONDITION_TOO_LONG_MSG,
         lambda: ddb.query(TableName=table, KeyConditionExpression=over_key,
                           ExpressionAttributeValues={**p, ":q": {"S": "x"}})),
    ]
    for label, want, fn in cases:
        code, msg = _error(fn)
        assert (code, msg) == ("ValidationException", want), f"{label} gave {code!r}: {msg!r}"

    page = ddb.scan(TableName=table, FilterExpression=at_filter, ExpressionAttributeValues=v,
                    ConsistentRead=True)
    assert (page["Count"], page["ScannedCount"]) == (0, 1), (
        f"Scan with a 4096-byte FilterExpression gave Count {page['Count']!r}, "
        f"ScannedCount {page['ScannedCount']!r}"
    )
    page = ddb.query(TableName=table, KeyConditionExpression="pk = :p", ExpressionAttributeValues=p,
                     ConsistentRead=True)
    assert page["Items"] == [item], f"Query pk = :p returned {page['Items']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
