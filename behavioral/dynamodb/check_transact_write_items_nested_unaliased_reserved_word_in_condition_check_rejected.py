"""transact-write-items-nested-unaliased-reserved-word-in-condition-check-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-nested-unaliased-reserved-word-in-condition-check-rejected"
GROUP = "transactions"
SERVICES = ["dynamodb"]

_RESERVED = "Invalid ConditionExpression: Attribute name is a reserved keyword; reserved keyword: status"


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
    """Poll DescribeTable every 2 s until the table is ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def _get(ddb, table, key):
    """The item at key read with ConsistentRead, or None."""
    return ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")


def _error(fn):
    """(Error.Code, Error.Message, CancellationReasons) of the ClientError fn() raises.

    An unexpected success fails, quoting the result.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message"), exc.response.get("CancellationReasons")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A reserved word used unaliased in a nested map path of a TransactWriteItems
    ConditionCheck's ConditionExpression is a top-level ValidationException; aliasing it commits.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ReservedWords.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-tw-nest-res-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    cc_key = {"pk": {"S": "cc"}}
    cc_item = {**cc_key, "m": {"M": {"status": {"S": "active"}}}}
    ddb.put_item(TableName=table, Item=cc_item)
    side_key = {"pk": {"S": "side"}}

    code, msg, reasons = _error(lambda: ddb.transact_write_items(TransactItems=[
        {"Put": {"TableName": table, "Item": {**side_key, "v": {"S": "1"}}}},
        {"ConditionCheck": {"TableName": table, "Key": cc_key, "ConditionExpression": "m.status = :v",
                             "ExpressionAttributeValues": {":v": {"S": "active"}}}},
    ]))
    assert (code, msg) == ("ValidationException", _RESERVED), (
        f"the unaliased nested reserved word gave {code!r}: {msg!r}")
    assert reasons is None, f"a top-level ValidationException must carry no CancellationReasons, got {reasons!r}"
    assert _get(ddb, table, side_key) is None, "the refused transaction must not have written its other Put"
    assert _get(ddb, table, cc_key) == cc_item, "the refused transaction must leave the cc item unchanged"

    # Positive control: the identical nested path, aliased, commits.
    ddb.transact_write_items(TransactItems=[
        {"Put": {"TableName": table, "Item": {**side_key, "v": {"S": "1"}}}},
        {"ConditionCheck": {"TableName": table, "Key": cc_key, "ConditionExpression": "#m.#status = :v",
                             "ExpressionAttributeNames": {"#m": "m", "#status": "status"},
                             "ExpressionAttributeValues": {":v": {"S": "active"}}}},
    ])
    assert _get(ddb, table, side_key) == {**side_key, "v": {"S": "1"}}, (
        "the aliased nested path must let the transaction commit and write the side item")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
