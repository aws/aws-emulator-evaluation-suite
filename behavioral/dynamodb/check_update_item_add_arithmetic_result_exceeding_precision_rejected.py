"""update-item-add-arithmetic-result-exceeding-precision-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-add-arithmetic-result-exceeding-precision-rejected"
GROUP = "negative-classes"
SERVICES = ["dynamodb"]

_BASE_NINES38 = "9" * 38  # 10**38 - 1, the largest 38-significant-digit integer
_OVERFLOW_MSG = "Number overflow. Attempting to store a number with magnitude larger than supported range"
_OVERFLOW_ERR = ("ValidationException", _OVERFLOW_MSG)


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises."""
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def _wait_active(ddb, ctx, table):
    """Poll DescribeTable every 2 s until the table is ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def expect_error(fn, code, message):
    """Raise if fn() succeeds; otherwise assert its exact (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert (err.get("Code"), err.get("Message")) == (code, message), (
            f"expected ({code!r}, {message!r}), got ({err.get('Code')!r}, {err.get('Message')!r})"
        )
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ADD whose arithmetic result would need 39 significant digits is the same ValidationException
    as a magnitude overflow, even far below the magnitude ceiling, and leaves the item unchanged;
    the same ADD held within the 38-digit limit succeeds.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-decaddprec-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    # The arithmetic result needs 39 significant digits (none of them trimmable: it starts
    # with a nonzero digit and ends with one). ADD refuses it and leaves the item unchanged.
    key = {"pk": {"S": "dec-add-overprecision"}}
    item = {**key, "bal": {"N": _BASE_NINES38}}
    ddb.put_item(TableName=table, Item=item)
    expect_error(
        lambda: ddb.update_item(
            TableName=table, Key=key, UpdateExpression="ADD bal :inc",
            ExpressionAttributeValues={":inc": {"N": "9"}},
        ),
        *_OVERFLOW_ERR,
    )
    got = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert got == item, f"refused ADD bal :inc changed the item to {got!r}"

    # Positive control: the same base ADD-ed by 1 lands at exactly 38 significant digits and
    # is accepted.
    r = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="ADD bal :one",
        ExpressionAttributeValues={":one": {"N": "1"}}, ReturnValues="ALL_NEW",
    )["Attributes"]
    want = {**key, "bal": {"N": "1" + "0" * 38}}
    assert r == want, f"ADD bal :one with bal={_BASE_NINES38!r} returned {r!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
