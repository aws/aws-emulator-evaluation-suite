"""conc-ddb-optimistic-refused-conditional-write-still-billed-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-ddb-optimistic-refused-conditional-write-still-billed-rejected"
GROUP = 'metric-emission'
SERVICES = ['cloudwatch', 'dynamodb']

WRITES = 10
ERR_CCF = 'ConditionalCheckFailedException'
_METRIC_BUDGET_S = 900
_POLL_S = 2.0


def _make_table(ctx, purpose):
    ddb = ctx.client('dynamodb')
    name = ctx.unique_name(f'sim2real-conc-ddb-opt-{purpose}-')
    ddb.create_table(
        TableName=name,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter('table_exists').wait(TableName=name, WaiterConfig={'Delay': 2, 'MaxAttempts': 250})
    return name


def _error(fn):
    """(code, response) for a call real AWS refuses. RAISES on unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response
    raise AssertionError(f'real AWS refuses this conditional write, but it SUCCEEDED: {result!r}')


def _wcu_sum(ctx, table, start):
    pts = ctx.client('cloudwatch').get_metric_statistics(
        Namespace='AWS/DynamoDB', MetricName='ConsumedWriteCapacityUnits',
        Dimensions=[{'Name': 'TableName', 'Value': table}],
        StartTime=start, EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
        Period=60, Statistics=['Sum'],
    )['Datapoints']
    return sum(p['Sum'] for p in pts)


def _poll_until_at_least(ctx, probe, target, description):
    """Poll probe() until it reaches target; return the value. RAISES on timeout with last value."""
    deadline = time.monotonic() + min(_METRIC_BUDGET_S, ctx.time_left())
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last >= target:
            return last
        time.sleep(_POLL_S)
    raise AssertionError(f'{description}: never reached {target} in {_METRIC_BUDGET_S}s; last {last!r}')


@tags("axis:rejection", "cap:c2", "concern:metrics", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Ten PutItems refused with ConditionalCheckFailedException change nothing and report no
    capacity in-band, yet ConsumedWriteCapacityUnits bills them exactly as a twin table is billed
    for ten successful conditional writes (11 units, seed write included)."""
    ddb = ctx.client('dynamodb')
    start = datetime.now(timezone.utc) - timedelta(minutes=2)
    subject = _make_table(ctx, 'lost')
    twin = _make_table(ctx, 'won')

    for table in (subject, twin):
        ddb.put_item(TableName=table, Item={'pk': {'S': 'k'}, 'version': {'N': '0'}})  # 1 WCU seed

    # Subject: every write holds a stale version and loses.
    for i in range(WRITES):
        code, resp = _error(lambda i=i: ddb.put_item(
            TableName=subject, Item={'pk': {'S': 'k'}, 'version': {'N': str(100 + i)}},
            ConditionExpression='version = :stale', ExpressionAttributeValues={':stale': {'N': '99'}},
            ReturnConsumedCapacity='TOTAL'))
        assert code == ERR_CCF, f'refused write {i}: expected {ERR_CCF}, got {code!r}'
        message = resp.get('Error', {}).get('Message')
        assert message == 'The conditional request failed', f'refused write {i}: message {message!r}'
        assert 'ConsumedCapacity' not in resp, (
            f'refused write {i} unexpectedly reported capacity in-band: {resp.get("ConsumedCapacity")!r}'
        )
    item = ddb.get_item(TableName=subject, Key={'pk': {'S': 'k'}}, ConsistentRead=True)['Item']
    assert item['version'] == {'N': '0'}, f'refused writes changed the item: {item!r}'

    # Twin: the identical shape, holding the right version every time, wins.
    twin_reported = 1.0
    for i in range(WRITES):
        resp = ddb.put_item(
            TableName=twin, Item={'pk': {'S': 'k'}, 'version': {'N': str(i + 1)}},
            ConditionExpression='version = :v', ExpressionAttributeValues={':v': {'N': str(i)}},
            ReturnConsumedCapacity='TOTAL')
        twin_reported += resp['ConsumedCapacity']['CapacityUnits']
    item = ddb.get_item(TableName=twin, Key={'pk': {'S': 'k'}}, ConsistentRead=True)['Item']
    assert item['version'] == {'N': str(WRITES)}, f'twin writes did not all apply: {item!r}'
    assert twin_reported == 1.0 + WRITES, f'twin in-band capacity {twin_reported!r}, expected {1 + WRITES}'

    twin_billed = _poll_until_at_least(ctx, lambda: _wcu_sum(ctx, twin, start), twin_reported,
                                       'twin ConsumedWriteCapacityUnits')
    assert twin_billed == twin_reported, (
        f'twin metered {twin_billed!r} WCU but reported {twin_reported!r} in-band'
    )
    subject_billed = _poll_until_at_least(ctx, lambda: _wcu_sum(ctx, subject, start), 1.0 + WRITES,
                                          'subject ConsumedWriteCapacityUnits (refused writes)')
    assert subject_billed == twin_billed, (
        f'{WRITES} refused conditional writes metered {subject_billed!r} WCU (seed included); the '
        f'same {WRITES} writes applied metered {twin_billed!r} -- a lost race must cost the same'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
