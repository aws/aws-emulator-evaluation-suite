"""update-item-set-arithmetic-result-over-38-significant-digits-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-set-arithmetic-result-over-38-significant-digits-rejected"
GROUP = "update-expression"
SERVICES = ["dynamodb"]

_MAX_38_NINES = "9" * 38
_CARRIED_1SIG = "1" + "0" * 38
_OVERFLOW_MSG = (
    "Number overflow. Attempting to store a number with magnitude larger than supported range"
)


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; in-use is retried every 2 s."""
    def run_undo():
        deadline = time.monotonic() + 300.0
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
    """Poll DescribeTable every 2 s until it is ACTIVE."""
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


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem SET arithmetic that carries a 38-nines N to a result spanning 39 significant
    digits is ValidationException; the item keeps its pre-update value.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-sigdig-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    key = {"pk": {"S": "oversig"}}
    item = {**key, "v": {"N": _MAX_38_NINES}}
    ddb.put_item(TableName=table, Item=item)

    code, msg = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET v = v + :two",
        ExpressionAttributeValues={":two": {"N": "2"}},
    ))
    assert (code, msg) == ("ValidationException", _OVERFLOW_MSG), (
        f"38-nines + 2 carries to a 39-significant-digit N; UpdateItem gave {code!r}: {msg!r}"
    )

    got = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert got == item, f"the refused SET left the item as {got!r}, expected it unchanged"

    control = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET v = v + :one",
        ExpressionAttributeValues={":one": {"N": "1"}}, ReturnValues="UPDATED_NEW",
    )
    assert control["Attributes"] == {"v": {"N": _CARRIED_1SIG}}, (
        "38-nines + 1 is the neighbouring one-significant-digit carry and must be accepted, "
        f"got {control['Attributes']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
