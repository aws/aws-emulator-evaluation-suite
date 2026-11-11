"""provisioned-write-throttle-reason-and-metric-agreement-rejected."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "provisioned-write-throttle-reason-and-metric-agreement-rejected"
GROUP = 'limits'
SERVICES = ['dynamodb']

_WCU = 1        # one 1 KB write per second, so the arithmetic below is exact
_RCU = 500      # reads exist only to verify; they must never be the subject
# 2x the wave's offered rate (~500 writes/s) and at one partition's ~1000 WCU/s ceiling, so the
# raised-capacity arm never depends on burst credit, which accrues far slower than documented.
_RAISED_WCU = 1000
_WAVE = 1000
# ~500 writes/s: wider waves approach the per-partition ~1000 WCU/s ceiling and get throttled by
# the partition rather than the configured capacity. Every wave uses the same width.
_WORKERS = 20
_BLOB = 'x' * 900  # -> 1 KB items, so 1 item == 1 WCU exactly
_THROTTLE_MSG = ('The level of configured provisioned throughput for the table was exceeded. '
                 'Consider increasing your provisioning level with the UpdateTable API.')
# A fresh 1-WCU table admits roughly 1,100 writes of burst credit across both waves, more than
# the ~300 s x 1 WCU the documentation implies. The padded ceiling still fails any limiter that
# admits an unbounded number of writes.
_BURST_CEILING = 1500


def _iso_floor(dt):
    return dt.replace(second=0, microsecond=0)


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/metrics-dimensions.html
@tags('axis:rejection', 'cap:c2', 'concern:data-plane', 'concern:negative-classes',
      'concern:metrics', 'dp:api', 'plane:data', "timing:real-time")
def run(ctx) -> None:
    """A 1-WCU table refuses over-rate writes with ProvisionedThroughputExceededException and table
    ThrottlingReasons; only accepted items exist, CloudWatch sums match client counts exactly, a
    paced writer is never refused, and raising WCU removes the refusals.
    """
    # Retries off on the load client: botocore retries ProvisionedThroughputExceededException,
    # which would absorb the refusals being counted. `max_attempts=N` means N+1 total attempts,
    # so the normalized total_max_attempts is what gets asserted.
    ddb = ctx.client('dynamodb', config=Config(retries={'total_max_attempts': 1},
                                               max_pool_connections=60))
    rd = ctx.client('dynamodb', config=Config(retries={'max_attempts': 12, 'mode': 'adaptive'},
                                              max_pool_connections=20))
    cw = ctx.client('cloudwatch')
    assert ddb.meta.config.retries['total_max_attempts'] == 1, (
        f'load client resolved retries to {ddb.meta.config.retries!r}, expected '
        'total_max_attempts == 1 (no retries at all)'
    )

    table = ctx.unique_name('sim2real-behav-provthr-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': _RCU, 'WriteCapacityUnits': _WCU},
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )

    def _drop_table():
        try:
            rd.delete_table(TableName=table)
        except ClientError as exc:
            if exc.response['Error']['Code'] != 'ResourceNotFoundException':
                raise

    ctx.on_cleanup(_drop_table)
    rd.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    arn = rd.describe_table(TableName=table)['Table']['TableArn']

    def _wave(prefix, n=_WAVE):
        def _put(key):
            try:
                resp = ddb.put_item(TableName=table,
                                    Item={'pk': {'S': key}, 'b': {'S': _BLOB}},
                                    ReturnConsumedCapacity='TOTAL')
                return key, resp['ConsumedCapacity']['CapacityUnits'], None
            except ClientError as exc:
                return key, None, exc.response
        t0 = time.time()
        with ThreadPoolExecutor(max_workers=_WORKERS) as ex:
            out = list(ex.map(_put, [f'{prefix}-{i:04d}' for i in range(n)]))
        return {
            'accepted': {k: cc for k, cc, err in out if err is None},
            'errors': {k: err for k, _, err in out if err is not None},
            'elapsed_s': time.time() - t0,
        }

    probe_lo = _iso_floor(datetime.now(timezone.utc))
    w1 = _wave('w1')
    w2 = _wave('w2')
    w2_end = datetime.now(timezone.utc)
    probe_hi = _iso_floor(w2_end) + timedelta(minutes=1)

    thr = dict(w1['errors'])
    thr.update({f'w2:{k}': v for k, v in w2['errors'].items()})
    accepted_total = len(w1['accepted']) + len(w2['accepted'])
    assert len(w1['errors']) > 0, (
        f'all {_WAVE} writes were accepted at {_WAVE / w1["elapsed_s"]:.0f}/s against a '
        f'{_WCU}-WCU table -- there is no provisioned-throughput limiter '
        f'(accepted {len(w1["accepted"])}, elapsed {w1["elapsed_s"]:.2f}s)'
    )

    codes = {r['Error']['Code'] for r in thr.values()}
    assert codes == {'ProvisionedThroughputExceededException'}, (
        f'over-rate writes were refused with {sorted(codes)!r}, expected exactly '
        "{'ProvisionedThroughputExceededException'}"
    )
    messages = {r['Error'].get('Message') for r in thr.values()}
    assert messages == {_THROTTLE_MSG}, (
        f'over-rate writes were refused with the messages {sorted(map(str, messages))!r}, '
        f'expected exactly {{{_THROTTLE_MSG!r}}}'
    )
    missing = [k for k, r in thr.items() if not r.get('ThrottlingReasons')]
    assert missing == [], (
        f'{len(missing)} of {len(thr)} throttles carried no ThrottlingReasons, e.g. '
        f'{missing[:3]!r} -- the modelled throttle diagnosis is absent'
    )
    reasons = {rr.get('reason') for r in thr.values() for rr in r['ThrottlingReasons']}
    assert reasons == {'TableWriteProvisionedThroughputExceeded'}, (
        f'ThrottlingReasons reported {sorted(reasons)!r}, expected exactly '
        "{'TableWriteProvisionedThroughputExceeded'} -- the reason must name the resource type, "
        'the operation type and the limit type that actually fired'
    )
    resources = {rr.get('resource') for r in thr.values() for rr in r['ThrottlingReasons']}
    assert resources == {arn}, (
        f'ThrottlingReasons named resources {sorted(resources)!r}, expected exactly the table ARN '
        f'{arn!r}'
    )

    # Per-item capacity metering: 1 KB items cost exactly 1 WCU, so the sum over accepted writes
    # must equal their count. A per-CALL meter, or a meter that rounds differently, fails here.
    units = sum(w1['accepted'].values()) + sum(w2['accepted'].values())
    assert units == accepted_total, (
        f'accepted writes reported {units} consumed capacity units for {accepted_total} 1 KB '
        f'items -- capacity must be metered per item size, not per call'
    )

    # Burst exhaustion: the second wave meets an emptied bucket, so it must be admitted far less
    # freely than the first. A fixed "reject after N requests" limiter cannot produce this split.
    assert len(w2['accepted']) < 0.5 * len(w1['accepted']), (
        f'wave 2 admitted {len(w2["accepted"])} writes against wave 1\'s '
        f'{len(w1["accepted"])} -- the accumulated burst credit was not consumed by wave 1, so '
        f'the limiter is not a token bucket'
    )
    assert accepted_total <= _BURST_CEILING, (
        f'{accepted_total} writes were admitted to a {_WCU}-WCU table inside '
        f'{w1["elapsed_s"] + w2["elapsed_s"]:.1f}s -- more than the measured burst ceiling of '
        f'{_BURST_CEILING} units, so admission does not track configured capacity'
    )

    # Negative space: EXACTLY the accepted keys exist, on a consistent read of the whole wave.
    keys = [f'w1-{i:04d}' for i in range(_WAVE)]
    found = set()
    for i in range(0, _WAVE, 100):
        request = {table: {'Keys': [{'pk': {'S': k}} for k in keys[i:i + 100]],
                           'ConsistentRead': True, 'ProjectionExpression': 'pk'}}
        while request:
            page = rd.batch_get_item(RequestItems=request)
            found |= {it['pk']['S'] for it in page['Responses'][table]}
            request = page.get('UnprocessedKeys') or None
    accepted_w1 = set(w1['accepted'])
    rejected_w1 = set(w1['errors'])
    assert found == accepted_w1, (
        f'a consistent read of all {_WAVE} wave-1 keys found {len(found)} items but '
        f'{len(accepted_w1)} were accepted; {len(found - accepted_w1)} unexpected and '
        f'{len(accepted_w1 - found)} missing (e.g. {sorted(found ^ accepted_w1)[:3]!r})'
    )
    assert found & rejected_w1 == set(), (
        f'{len(found & rejected_w1)} throttled keys are present in the table, e.g. '
        f'{sorted(found & rejected_w1)[:3]!r} -- a refused PutItem must leave no item'
    )

    # Wait past probe_hi so later writes stay out of the metric minute buckets, and at least 60 s
    # after wave 2 so the drained token bucket refills before the paced control writer runs.
    quiesce_until = max(probe_hi + timedelta(seconds=3), w2_end + timedelta(seconds=60))
    while datetime.now(timezone.utc) < quiesce_until:
        time.sleep(1)

    # In-limit control: a paced writer at 1 write / 1.3 s is inside 1 WCU/s and must never be
    # refused -- so the refusals above came from the rate, not from the table being broken.
    ctl_keys = [f'ctl-{i:02d}' for i in range(15)]
    ctl_errors = {}
    for k in ctl_keys:
        try:
            ddb.put_item(TableName=table, Item={'pk': {'S': k}, 'b': {'S': _BLOB}})
        except ClientError as exc:
            ctl_errors[k] = exc.response['Error']['Code']
        time.sleep(1.3)
    assert ctl_errors == {}, (
        f'the paced in-limit control writer was refused on {sorted(ctl_errors)!r} -- a writer '
        f'inside the configured 1 WCU/s must always be admitted'
    )
    ctl_found = {it['pk']['S'] for it in rd.batch_get_item(
        RequestItems={table: {'Keys': [{'pk': {'S': k}} for k in ctl_keys],
                              'ConsistentRead': True, 'ProjectionExpression': 'pk'}}
    )['Responses'][table]}
    assert ctl_found == set(ctl_keys), (
        f'the control writer\'s items read back as {sorted(ctl_found)!r}, expected all 15 of '
        f'{ctl_keys!r}'
    )

    # Failure arm: raise the configured capacity and replay the identical wave. Zero refusals are
    # permitted. This is the arm that catches a limiter keyed on request count rather than on the
    # capacity the table is configured with.
    rd.update_table(TableName=table,
                    ProvisionedThroughput={'ReadCapacityUnits': _RCU,
                                           'WriteCapacityUnits': _RAISED_WCU})
    deadline = time.time() + 180
    while time.time() < deadline:
        desc = rd.describe_table(TableName=table)['Table']
        if (desc['TableStatus'] == 'ACTIVE'
                and desc['ProvisionedThroughput']['WriteCapacityUnits'] == _RAISED_WCU):
            break
        time.sleep(3)
    else:
        raise AssertionError(
            f'table did not report {_RAISED_WCU} WCU and ACTIVE within 180s of UpdateTable'
        )
    # The earlier waves drained the bucket, so let it refill for 60 s after the raise; retry within
    # a bound so a slower refill costs wall clock rather than a false failure.
    quiesce_deadline = time.time() + 240
    w3 = None
    while True:
        time.sleep(60 if w3 is None else 20)
        w3 = _wave('w3')
        if not w3['errors'] or time.time() >= quiesce_deadline:
            break
    assert w3['errors'] == {}, (
        f'{len(w3["errors"])} of {_WAVE} writes were refused at {_RAISED_WCU} WCU '
        f'({_WAVE / w3["elapsed_s"]:.0f}/s offered) -- the limiter is not tracking the configured '
        f'capacity; codes were '
        f'{ {r["Error"]["Code"] for r in w3["errors"].values()} !r}'
    )
    assert len(w3['accepted']) == _WAVE, (
        f'only {len(w3["accepted"])} of {_WAVE} writes were accepted at {_RAISED_WCU} WCU'
    )

    # Metric agreement, not presence. Polled because DynamoDB metrics take ~80-100 s to land and
    # converge monotonically upward to the exact count.
    def _metric_sum(name, dims):
        return sum(p['Sum'] for p in cw.get_metric_statistics(
            Namespace='AWS/DynamoDB', MetricName=name, Dimensions=dims,
            StartTime=probe_lo, EndTime=probe_hi, Period=60, Statistics=['Sum'])['Datapoints'])

    want = {
        'ThrottledRequests': (len(thr), [{'Name': 'TableName', 'Value': table},
                                         {'Name': 'Operation', 'Value': 'PutItem'}]),
        'WriteThrottleEvents': (len(thr), [{'Name': 'TableName', 'Value': table}]),
        'ConsumedWriteCapacityUnits': (accepted_total,
                                       [{'Name': 'TableName', 'Value': table}]),
    }
    # The probe waves are already ~150 s old here, past the metric ingestion latency, so 130 s of
    # slack is enough and keeps the check's total runtime bounded.
    seen = {}
    deadline = time.time() + 130
    while True:
        seen = {n: _metric_sum(n, d) for n, (_, d) in want.items()}
        if all(seen[n] == want[n][0] for n in want):
            break
        if time.time() >= deadline:
            break
        time.sleep(15)
    for name, (expected, _) in want.items():
        assert seen[name] == expected, (
            f'AWS/DynamoDB {name} Sum over the probe window is {seen[name]!r} but the client '
            f'observed {expected} -- the metric must be derived from the same counter that '
            f'produced the refusals, not from a request log (all metrics: {seen!r})'
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
