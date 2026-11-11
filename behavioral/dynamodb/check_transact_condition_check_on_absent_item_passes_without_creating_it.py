"""transact-condition-check-on-absent-item-passes-without-creating-it."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-condition-check-on-absent-item-passes-without-creating-it"
GROUP = "transactions"
SERVICES = ["dynamodb"]

_CCF_SECOND = (
    "Transaction cancelled, please refer cancellation reasons for specific reasons "
    "[ConditionalCheckFailed, None]"
)
_CCF_REASON = "The conditional request failed"


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
    """(Error.Code, Error.Message, CancellationReasons) of the ClientError fn() raises.

    An unexpected success fails, quoting the result.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message"), exc.response.get("CancellationReasons")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _get(ddb, table, key):
    """The item at key read with ConsistentRead, or None."""
    return ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A ConditionCheck attribute_not_exists(pk) on a key with no item passes, its Put commits and the
    checked key stays absent; once that key exists the same transaction cancels and writes nothing.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ConditionCheck.html
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb, "sim2real-behav-ddb-txabs-")
    ghost = {"pk": {"S": "ghost"}}

    def transact(pk):
        return ddb.transact_write_items(TransactItems=[
            {"ConditionCheck": {"TableName": table, "Key": ghost,
                                "ConditionExpression": "attribute_not_exists(pk)"}},
            {"Put": {"TableName": table, "Item": {"pk": {"S": pk}, "v": {"S": "ok"}}}},
        ])

    transact("after-ghost")
    got = _get(ddb, table, {"pk": {"S": "after-ghost"}})
    assert got == {"pk": {"S": "after-ghost"}, "v": {"S": "ok"}}, f"the Put behind a passing check stored {got!r}"
    checked = _get(ddb, table, ghost)
    assert checked is None, f"a ConditionCheck on an absent key created {checked!r}"

    ddb.put_item(TableName=table, Item={**ghost, "v": {"S": "now-present"}})
    code, msg, reasons = _error(lambda: transact("after-present"))
    assert (code, msg) == ("TransactionCanceledException", _CCF_SECOND), (
        f"the check against a present item gave {code!r}: {msg!r}"
    )
    got_reasons = [(r.get("Code"), r.get("Message")) for r in reasons or []]
    assert got_reasons == [("ConditionalCheckFailed", _CCF_REASON), ("None", None)], (
        f"cancellation reasons were {reasons!r}"
    )
    assert _get(ddb, table, {"pk": {"S": "after-present"}}) is None, "a cancelled transaction wrote its Put"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
