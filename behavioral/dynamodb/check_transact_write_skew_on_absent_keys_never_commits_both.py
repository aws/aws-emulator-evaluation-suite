"""transact-write-skew-on-absent-keys-never-commits-both."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-skew-on-absent-keys-never-commits-both"
GROUP = "transactions"
SERVICES = ["dynamodb"]

_ROUNDS = 15
_CANCELLED_PREFIX = "Transaction cancelled, please refer cancellation reasons for specific reasons "
_REASON_CODES = {"None", "ConditionalCheckFailed", "TransactionConflict"}


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


def _get(ddb, table, key):
    """The item at key read with ConsistentRead, or None."""
    return ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two concurrent transactions that each check the other's absent key and write their own never
    both commit and at least one commits; each failure is TransactionCanceledException naming a
    failing item, and only committed writes are stored.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb, "sim2real-behav-ddb-txskew-")

    def attempt(barrier, check_pk, put_pk):
        """Run [ConditionCheck absent(check_pk), Put put_pk]; return None or (code, msg, reasons)."""
        barrier.wait(timeout=60)
        try:
            ddb.transact_write_items(TransactItems=[
                {"ConditionCheck": {"TableName": table, "Key": {"pk": {"S": check_pk}},
                                    "ConditionExpression": "attribute_not_exists(pk)"}},
                {"Put": {"TableName": table, "Item": {"pk": {"S": put_pk}}}},
            ])
            return None
        except ClientError as exc:
            err = exc.response["Error"]
            return err.get("Code"), err.get("Message"), exc.response.get("CancellationReasons")

    committed = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        for r in range(_ROUNDS):
            x, y = f"x-{r:02d}", f"y-{r:02d}"
            barrier = threading.Barrier(2)
            fx = pool.submit(attempt, barrier, y, x)
            fy = pool.submit(attempt, barrier, x, y)
            outcomes = {x: fx.result(), y: fy.result()}
            assert any(o is not None for o in outcomes.values()), (
                f"round {r}: both transactions committed, each having seen the other's key absent"
            )
            for pk, outcome in outcomes.items():
                stored = _get(ddb, table, {"pk": {"S": pk}})
                if outcome is None:
                    assert stored == {"pk": {"S": pk}}, f"round {r}: committed Put {pk!r} reads {stored!r}"
                    committed.append(pk)
                    continue
                code, msg, reasons = outcome
                codes = [reason.get("Code") for reason in reasons or []]
                expected = _CANCELLED_PREFIX + "[" + ", ".join(str(c) for c in codes) + "]"
                assert (code, msg) == ("TransactionCanceledException", expected), (
                    f"round {r}: the transaction writing {pk!r} failed with {code!r}: {msg!r}"
                )
                assert len(codes) == 2 and set(codes) <= _REASON_CODES, (
                    f"round {r}: the cancellation of {pk!r} carried reasons {reasons!r}"
                )
                assert any(c != "None" for c in codes), (
                    f"round {r}: the cancellation of {pk!r} names no failing item: {reasons!r}"
                )
                assert stored is None, f"round {r}: cancelled Put {pk!r} was stored as {stored!r}"
    assert committed, f"no transaction committed in {_ROUNDS!r} rounds: {committed!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
