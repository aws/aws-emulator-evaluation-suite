"""concurrent-tag-resource-no-lost-tags."""
from __future__ import annotations

import time


from behavioral_harness import tags

CHECK = "concurrent-tag-resource-no-lost-tags"
GROUP = 'concurrency'
SERVICES = ['dynamodb']


def _poll_until(probe, predicate, *, timeout_s=30, interval_s=2.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N concurrent TagResource calls, each adding a DISTINCT tag key to the SAME table ARN, must
    all durably apply -- a read-modify-write race on the resource's tag set must not silently drop
    a concurrently-added sibling key.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=t, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    arn = ddb.describe_table(TableName=t)['Table']['TableArn']
    n = 10
    keys = [f'concurrent-tag-{i}' for i in range(n)]

    def _add_tag(k):
        return ddb.tag_resource(ResourceArn=arn, Tags=[{'Key': k, 'Value': 'v'}])

    results = _run_concurrent([lambda k=k: _add_tag(k) for k in keys], timeout_s=90)
    successes = _concurrent_successes(results)
    assert successes == n, f'expected all {n} TagResource calls to succeed, got {successes}: {results}'

    final_tags = _poll_until(
        lambda: {tag['Key'] for tag in ddb.list_tags_of_resource(ResourceArn=arn)['Tags']},
        lambda present: set(keys) <= present,
        timeout_s=30,
        interval_s=2.0,
        description='all concurrently-added tag keys present',
    )
    missing = set(keys) - final_tags
    assert not missing, f'lost tag keys under concurrent TagResource: {missing}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
