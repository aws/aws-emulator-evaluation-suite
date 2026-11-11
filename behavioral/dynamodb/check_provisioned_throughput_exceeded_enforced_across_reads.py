"""provisioned-throughput-exceeded-enforced-across-reads."""
from __future__ import annotations

from typing import Callable

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "provisioned-throughput-exceeded-enforced-across-reads"
GROUP = 'limits'
SERVICES = ['dynamodb']


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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent GetItem, Query, Scan, BatchGetItem and TransactGetItems against a 1-RCU table
    raise ProvisionedThroughputExceededException on at least one read op; which ops are throttled
    depends on undocumented burst credit and arrival order, so no single op is required."""
    # Retries off: botocore would otherwise retry away the throttling errors this check counts.
    ddb = ctx.client('dynamodb', config=Config(retries={'total_max_attempts': 1}))
    assert ddb.meta.config.retries['total_max_attempts'] == 1, (
        f'load client resolved retries to {ddb.meta.config.retries!r}, expected '
        'total_max_attempts == 1 (no retries at all)'
    )
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'S'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': 1, 'WriteCapacityUnits': 400},
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # Large items make each consistent read cost many RCU, exhausting burst credit quickly.
    big = 'x' * 200_000
    pk = 'throughput-pk'
    for i in range(5):
        ddb.put_item(TableName=t, Item={'pk': {'S': pk}, 'sk': {'S': f'{i:03d}'}, 'blob': {'S': big}})

    # Positive control: an unloaded read succeeds, so rejecting every read cannot pass.
    ctl_pk, ctl_sk = 'throughput-control', 'ctl'
    ddb.put_item(TableName=t, Item={'pk': {'S': ctl_pk}, 'sk': {'S': ctl_sk}, 'v': {'S': 'ok'}})
    ctl_resp = ddb.get_item(
        TableName=t, Key={'pk': {'S': ctl_pk}, 'sk': {'S': ctl_sk}}, ConsistentRead=True
    )
    assert ctl_resp.get('Item', {}).get('v', {}).get('S') == 'ok', (
        f'a single unloaded consistent GetItem before any load returned '
        f'{ctl_resp.get("Item")!r}, expected the control item -- the table must serve ordinary '
        f'reads correctly before throughput enforcement is exercised'
    )

    ops: dict[str, Callable] = {
        'GetItem': lambda: ddb.get_item(
            TableName=t, Key={'pk': {'S': pk}, 'sk': {'S': '000'}}, ConsistentRead=True
        ),
        'Query': lambda: ddb.query(
            TableName=t,
            KeyConditionExpression='pk = :p',
            ExpressionAttributeValues={':p': {'S': pk}},
            ConsistentRead=True,
        ),
        'Scan': lambda: ddb.scan(TableName=t, ConsistentRead=True),
        'BatchGetItem': lambda: ddb.batch_get_item(
            RequestItems={
                t: {
                    'Keys': [{'pk': {'S': pk}, 'sk': {'S': f'{i:03d}'}} for i in range(5)],
                    'ConsistentRead': True,
                }
            }
        ),
        'TransactGetItems': lambda: ddb.transact_get_items(
            TransactItems=[{'Get': {'TableName': t, 'Key': {'pk': {'S': pk}, 'sk': {'S': '000'}}}}]
        ),
    }

    def _one_wave(per_op_n):
        fns = []
        labels = []
        for label, fn in ops.items():
            for _ in range(per_op_n):
                fns.append(fn)
                labels.append(label)
        results = _run_concurrent(fns, timeout_s=60)
        codes_by_op = {label: set() for label in ops}
        for label, r in zip(labels, results):
            if isinstance(r, ClientError):
                codes_by_op[label].add(r.response.get('Error', {}).get('Code'))
        return codes_by_op

    # A brand-new table may still carry a little burst credit; spend it in a first wave, then
    # assert enforcement on an immediately-following second wave.
    _one_wave(per_op_n=6)
    codes_by_op = _one_wave(per_op_n=6)

    throttle_codes = {'ProvisionedThroughputExceededException'}
    triggered = {op: codes for op, codes in codes_by_op.items() if codes & throttle_codes}
    assert triggered, (
        f'expected ProvisionedThroughputExceededException on at least one read op under load '
        f'against a 1-RCU table, observed: {codes_by_op}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
