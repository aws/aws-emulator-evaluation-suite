"""update-item-condition-expression-over-4096-bytes-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-condition-expression-over-4096-bytes-rejected"
GROUP = "validation"
SERVICES = ["dynamodb"]


def _teardown(undo, *not_found: str, timeout_s: float = 300.0):
    """A cleanup running undo() where a failed delete raises; in-use is retried every 2 s."""
    def run_undo() -> None:
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


def _wait_active(ddb, ctx, table: str) -> dict:
    """Poll DescribeTable every 2 s until the table is ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE":
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem refuses a ConditionExpression over 4096 bytes as ValidationException and
    leaves the item unchanged; a well-formed ConditionExpression in the same shape still applies.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-upd-cond-size-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    ddb.put_item(TableName=table, Item={"pk": {"S": "k1"}, "val": {"S": "orig"}})

    # Positive control: a well-formed ConditionExpression still applies the update.
    ddb.update_item(
        TableName=table, Key={"pk": {"S": "k1"}},
        UpdateExpression="SET val = :v",
        ConditionExpression="attribute_exists(pk)",
        ExpressionAttributeValues={":v": {"S": "updated-control"}},
    )
    got = ddb.get_item(TableName=table, Key={"pk": {"S": "k1"}}, ConsistentRead=True)["Item"]
    assert got == {"pk": {"S": "k1"}, "val": {"S": "updated-control"}}, (
        f"positive control: UpdateItem with a well-formed ConditionExpression read back {got!r}"
    )

    over_4kb = "attribute_exists(pk)" + " " * (4097 - len("attribute_exists(pk)"))
    assert len(over_4kb) == 4097, f"ConditionExpression length {len(over_4kb)!r}, expected 4097"

    code, msg = _error(lambda: ddb.update_item(
        TableName=table, Key={"pk": {"S": "k1"}},
        UpdateExpression="SET val = :v",
        ConditionExpression=over_4kb,
        ExpressionAttributeValues={":v": {"S": "should-not-apply"}},
    ))
    assert (code, msg) == (
        "ValidationException",
        "1 validation error detected: Invalid ConditionExpression: Expression size has exceeded "
        "the maximum allowed size;",
    ), f"UpdateItem with a 4097-byte ConditionExpression gave {code!r}: {msg!r}"

    got = ddb.get_item(TableName=table, Key={"pk": {"S": "k1"}}, ConsistentRead=True)["Item"]
    assert got == {"pk": {"S": "k1"}, "val": {"S": "updated-control"}}, (
        f"a rejected ConditionExpression must not change the item, got {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
