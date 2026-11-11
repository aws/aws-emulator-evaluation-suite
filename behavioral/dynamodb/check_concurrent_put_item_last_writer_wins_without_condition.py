"""concurrent-put-item-last-writer-wins-without-condition."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-put-item-last-writer-wins-without-condition"
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Ten concurrent unconditional PutItem calls to one key all succeed, and consistent reads
    afterwards keep returning the same single writer's value, never flapping between candidates."""
    ddb = ctx.client("dynamodb")
    name = _simple_table(ddb, ctx)
    key = {"pk": {"S": "lww-1"}}
    n = 10
    values = [f"writer-{i}" for i in range(n)]

    def _make_writer(v: str):
        def _put():
            return ddb.put_item(TableName=name, Item={**key, "writer": {"S": v}})

        return _put

    results = _run_concurrent([_make_writer(v) for v in values])
    successes = _concurrent_successes(results)
    assert successes == n, f"unconditional PutItem calls must all succeed, got {successes}/{n}: {results}"
    codes = _concurrent_error_codes(results)
    assert codes == [], f"unconditional PutItem must never fail with a conditional error: {codes}"

    final = ddb.get_item(TableName=name, Key=key, ConsistentRead=True)["Item"]
    assert final["writer"]["S"] in values, final

    for _ in range(3):
        again = ddb.get_item(TableName=name, Key=key, ConsistentRead=True)["Item"]
        assert again["writer"]["S"] == final["writer"]["S"], (again, final)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
