"""concurrent-create-table-single-winner."""
from __future__ import annotations

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "concurrent-create-table-single-winner"
GROUP = 'concurrency'
SERVICES = ['dynamodb']
ERR_RESOURCE_IN_USE = 'ResourceInUseException'


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """N concurrent CreateTable calls racing to create a table with the SAME name must yield
    EXACTLY ONE winner; every other racer gets ResourceInUseException, and the table ends up
    existing exactly once. Tagged axis:rejection: the graded half is the losers' error code.
    """
    ddb = ctx.client('dynamodb')
    name = ctx.unique_name('sim2real-behav-race-tbl-')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    n = 8

    def _try_create():
        return ddb.create_table(
            TableName=name,
            KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST',
            Tags=[{'Key': 'sim2real', 'Value': CHECK}],
        )

    results = _run_concurrent([_try_create for _ in range(n)], timeout_s=90)
    successes = _concurrent_successes(results)
    assert successes == 1, f'expected exactly one winning CreateTable, got {successes}: {results}'

    winner = next(r for r in results if not isinstance(r, BaseException))
    assert winner['TableDescription']['TableName'] == name, winner

    codes = _concurrent_error_codes(results)
    assert len(codes) == n - 1, codes
    assert all(c == ERR_RESOURCE_IN_USE for c in codes), codes
    expected = f'Attempt to change a resource which is still in use: Table is being created: {name}'
    messages = [r.response.get('Error', {}).get('Message') for r in results if isinstance(r, ClientError)]
    assert messages == [expected] * (n - 1), f'expected every loser to get {expected!r}, got {messages!r}'

    ddb.get_waiter('table_exists').wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    described = ddb.describe_table(TableName=name)['Table']
    assert described['TableName'] == name, described


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
