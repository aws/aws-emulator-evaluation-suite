"""execute-statement-conditional-update-failure."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-conditional-update-failure"
GROUP = 'concurrency'
SERVICES = ['dynamodb']

_TAGS_KV = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _wait_table_active(ddb, table_name, timeout_s=90.0, interval_s=1.0):
    """Poll DescribeTable until the table AND every GSI on it report ACTIVE."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ddb.describe_table(TableName=table_name)["Table"]
        if last["TableStatus"] == "ACTIVE" and all(
            idx.get("IndexStatus", "ACTIVE") == "ACTIVE"
            for idx in last.get("GlobalSecondaryIndexes", [])
        ):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never went ACTIVE in {timeout_s}s: {last!r}")


def _simple_table(ddb, ctx, *, prefix="sim2real-behav-ddb-tbl-"):
    """Create a single-"pk" (S) hash-key table, register teardown, wait ACTIVE, return the name."""
    name = ctx.unique_name(prefix)
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=_TAGS_KV,
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    _wait_table_active(ddb, name)
    return name


def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _concurrent_successes(results):
    return sum((1 for r in results if not isinstance(r, BaseException)))


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent PartiQL `UPDATE ... WHERE pk = ? AND counter = 0` statements yield exactly one winner; every other
    raises ConditionalCheckFailedException ("The conditional request failed") and the counter ends at 1.
    """
    ddb = ctx.client("dynamodb")
    name = _simple_table(ddb, ctx)
    pk = "pql-cond-1"
    ddb.put_item(TableName=name, Item={"pk": {"S": pk}, "counter": {"N": "0"}})

    def _try_claim():
        return ddb.execute_statement(
            Statement=f'UPDATE "{name}" SET counter = ? WHERE pk = ? AND counter = ?',
            Parameters=[{"N": "1"}, {"S": pk}, {"N": "0"}],
        )

    n = 8
    results = _run_concurrent([_try_claim for _ in range(n)])
    successes = _concurrent_successes(results)
    assert successes == 1, f"expected exactly one PartiQL UPDATE to win the race, got {successes}: {results}"

    codes = _concurrent_error_codes(results)
    assert len(codes) == n - 1, f"expected {n - 1} losing racers, got {len(codes)}: {codes}"
    assert all(c == "ConditionalCheckFailedException" for c in codes), (
        f"expected every losing racer to get ConditionalCheckFailedException, got {codes}"
    )
    messages = [r.response.get("Error", {}).get("Message") for r in results if isinstance(r, ClientError)]
    assert messages == ["The conditional request failed"] * (n - 1), (
        f"expected every losing racer to get the message 'The conditional request failed', got {messages}"
    )

    final = ddb.get_item(TableName=name, Key={"pk": {"S": pk}}, ConsistentRead=True)["Item"]
    assert final["counter"] == {"N": "1"}, (
        f"exactly one PartiQL UPDATE must have applied, got counter={final['counter']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
