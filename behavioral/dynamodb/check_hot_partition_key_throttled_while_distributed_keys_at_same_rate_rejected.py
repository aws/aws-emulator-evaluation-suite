"""hot-partition-key-throttled-while-distributed-keys-at-same-rate-rejected."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hot-partition-key-throttled-while-distributed-keys-at-same-rate-rejected"
GROUP = 'limits'
SERVICES = ['dynamodb']

# 4000 WCU forces DynamoDB to spread the table over >= ceil(4000/1000) == 4 partitions, each
# carrying ~1000 WCU/s of the table's budget. 3000 RCU exists only so the server-side verification
# reads are not themselves the subject; ceil(3000/3000) == 1, so it does not change the partition
# count and therefore does not change what the write arms measure.
_WCU = 4000
_RCU = 3000
# Offered write rate, identical for every arm. 2500/s is comfortably under the table's 4000 WCU/s
# and comfortably over one partition's ~1000 WCU/s. That gap is the experiment: at this rate the
# table ceiling can never be the binding constraint, so a throttle can only come from a
# partition-level limiter.
_TARGET = 2500
_ARM_S = 10
_DIST_KEYS = 50
_QUIESCE_S = 20
# On AWS a single hot key lands at the ~1000 WCU/s per-partition-key ceiling (adaptive capacity
# does not absorb it) with reason 'TableWriteKeyRangeThroughputExceeded'. Writes are paced because
# an unpaced driver exceeds the table ceiling and throttles both arms.
_BLOB = 'x' * 900  # -> 1 KB items, so 1 item == 1 WCU exactly and the arithmetic is checkable


def _paced_arm(ddb, table, label, keyfn, *, target, duration_s, n_probe=6):
    """Drive `target` writes/s of 1 KB items for `duration_s` and report what the service did.

    BatchWriteItem carries the load (throttles surface as UnprocessedItems); single PutItem probes
    run alongside because only the exception carries ThrottlingReasons."""
    n_batches = int(duration_s * target / 25)
    lock = threading.Lock()
    st = {'accepted': 0, 'unprocessed': 0, 'calls': 0, 'codes': {}, 'reasons': set(),
          'resources': set(), 'unprocessed_sks': [], 'probe_accepted': 0}
    nxt = [0]
    t0 = time.time()

    def _record_error(exc):
        resp = exc.response
        with lock:
            code = resp['Error']['Code']
            st['codes'][code] = st['codes'].get(code, 0) + 1
            for reason in resp.get('ThrottlingReasons') or []:
                st['reasons'].add(reason.get('reason'))
                st['resources'].add(reason.get('resource'))

    def _batch_writer():
        while True:
            with lock:
                b = nxt[0]
                if b >= n_batches:
                    return
                nxt[0] += 1
            slack = (t0 + (b * 25) / target) - time.time()
            if slack > 0:
                time.sleep(slack)
            base = b * 25
            items = [{'PutRequest': {'Item': {'pk': {'S': keyfn(base + j)},
                                              'sk': {'S': f'{label}-{base + j:07d}'},
                                              'b': {'S': _BLOB}}}} for j in range(25)]
            try:
                resp = ddb.batch_write_item(RequestItems={table: items})
                left = resp.get('UnprocessedItems', {}).get(table, [])
                with lock:
                    st['calls'] += 1
                    st['unprocessed'] += len(left)
                    st['accepted'] += 25 - len(left)
                    st['unprocessed_sks'].extend(
                        w['PutRequest']['Item']['sk']['S'] for w in left)
            except ClientError as exc:
                _record_error(exc)

    def _probe(wid):
        n = 0
        deadline = t0 + duration_s
        while time.time() < deadline:
            n += 1
            try:
                ddb.put_item(TableName=table,
                             Item={'pk': {'S': keyfn(n * 7919 + wid * 13)},
                                   'sk': {'S': f'{label}-p{wid}-{n:06d}'},
                                   'b': {'S': _BLOB}})
                with lock:
                    st['probe_accepted'] += 1
            except ClientError as exc:
                _record_error(exc)
            time.sleep(0.15)

    with ThreadPoolExecutor(max_workers=110) as ex:
        futures = [ex.submit(_batch_writer) for _ in range(100)]
        futures += [ex.submit(_probe, w) for w in range(n_probe)]
        for f in futures:
            f.result()

    st['elapsed_s'] = time.time() - t0
    st['offered'] = n_batches * 25
    st['landed'] = st['accepted'] + st['probe_accepted']
    st['rate'] = st['landed'] / st['elapsed_s']
    return st


def _count_pk(ddb, table, pk):
    """Strongly-consistent server-side count of the items under one partition key, paginated."""
    total, start = 0, None
    while True:
        kw = dict(TableName=table, KeyConditionExpression='pk = :p',
                  ExpressionAttributeValues={':p': {'S': pk}},
                  Select='COUNT', ConsistentRead=True)
        if start:
            kw['ExclusiveStartKey'] = start
        page = ddb.query(**kw)
        total += page['Count']
        start = page.get('LastEvaluatedKey')
        if not start:
            return total


@tags('axis:rejection', 'cap:c2', 'concern:data-plane', 'concern:negative-classes',
      'dp:api', 'plane:data')
def run(ctx) -> None:
    """At one offered write rate, writes to a single partition key are throttled with the
    TableWriteKeyRangeThroughputExceeded reason, while the same rate over 50 keys is not throttled;
    4 keys land in between, and throttled writes never persist."""
    # The load client has retries off so a retry cannot absorb a throttle; the read-back client
    # retries because a throttled verification read is not a finding.
    ddb = ctx.client('dynamodb', config=Config(retries={'total_max_attempts': 1},
                                               max_pool_connections=120))
    rd = ctx.client('dynamodb', config=Config(retries={'max_attempts': 12, 'mode': 'adaptive'},
                                              max_pool_connections=20))
    # botocore spells "N retries" as total_max_attempts == N+1 and applies it independently of the
    # retry mode, so assert the NORMALIZED value rather than trusting the Config that was passed.
    assert ddb.meta.config.retries['total_max_attempts'] == 1, (
        f'load client resolved retries to {ddb.meta.config.retries!r}, '
        'expected total_max_attempts == 1 (no retries at all)'
    )
    assert rd.meta.config.retries['total_max_attempts'] == 13, (
        f'verification client resolved retries to {rd.meta.config.retries!r}, '
        'expected total_max_attempts == 13'
    )

    table = ctx.unique_name('sim2real-behav-hotpart-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'},
                   {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                              {'AttributeName': 'sk', 'AttributeType': 'S'}],
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

    # Warm the table across the whole distributed key space at a rate no partition can throttle,
    # so both measured arms meet an already-split, already-baselined table.
    warm = _paced_arm(ddb, table, 'warm', lambda i: f'd{i % _DIST_KEYS}',
                      target=500, duration_s=4, n_probe=0)
    assert warm['unprocessed'] == 0 and warm['codes'] == {}, (
        f'the 500/s warm-up was itself throttled: {warm["unprocessed"]} unprocessed, codes '
        f'{warm["codes"]!r} -- the table cannot carry even 1/8 of its provisioned write capacity'
    )

    # Arm B (distributed) runs FIRST, so a failure here can never be explained as damage left
    # behind by the hot arm.
    time.sleep(_QUIESCE_S)
    dist = _paced_arm(ddb, table, 'DIST', lambda i: f'd{i % _DIST_KEYS}',
                      target=_TARGET, duration_s=_ARM_S)
    time.sleep(_QUIESCE_S)
    hot = _paced_arm(ddb, table, 'HOT', lambda i: 'hot', target=_TARGET, duration_s=_ARM_S)
    time.sleep(_QUIESCE_S)
    # Continuity arm: four partition keys. If the limiter tracks key cardinality continuously
    # rather than special-casing a literal single-key writer, throttling must land strictly
    # between the two measured arms.
    four = _paced_arm(ddb, table, 'FOUR', lambda i: f'h{i % 4}',
                      target=_TARGET, duration_s=_ARM_S)

    # The comparison is only valid if the arms offered the same load and the driver was not
    # itself the bottleneck.
    assert dist['offered'] == hot['offered'] == four['offered'], (
        f'arms offered different loads: dist={dist["offered"]} hot={hot["offered"]} '
        f'four={four["offered"]} -- the comparison would be void'
    )
    # 0.6 x 2500/s is still 1.5x one partition key's ~1000 WCU/s, so the hot arm is over its ceiling.
    assert dist['rate'] >= 0.6 * _TARGET, (
        f'the distributed arm achieved only {dist["rate"]:.0f} writes/s against an offered '
        f'{_TARGET}/s while spending no throttling budget -- the driver, not the service, was the '
        f'bottleneck, so the two arms are not at the same rate ({dist!r})'
    )

    assert dist['unprocessed'] == 0, (
        f'{dist["unprocessed"]} of {dist["offered"]} distributed writes came back unprocessed at '
        f'{dist["rate"]:.0f}/s against {_WCU} provisioned WCU -- a well-spread writer inside the '
        f'table budget must not be throttled'
    )
    assert dist['codes'] == {}, (
        f'the distributed arm raised {dist["codes"]!r}; expected no errors at all'
    )
    assert dist['reasons'] == set(), (
        f'the distributed arm reported throttling reasons {sorted(dist["reasons"])!r}; a writer '
        'spread over 50 keys inside the table budget has no reason to be throttled'
    )

    # The hot arm is throttled, and named as a key-range throttle.
    assert hot['unprocessed'] > 0, (
        f'all {hot["offered"]} writes to the single partition key "hot" were accepted at '
        f'{hot["rate"]:.0f}/s -- there is no partition-level limiter ({hot!r})'
    )
    assert set(hot['codes']) == {'ProvisionedThroughputExceededException'}, (
        f'the hot arm\'s single-item probes raised {hot["codes"]!r}; expected exactly '
        'ProvisionedThroughputExceededException and nothing else'
    )
    assert hot['reasons'] == {'TableWriteKeyRangeThroughputExceeded'}, (
        f'the hot arm reported throttling reasons {sorted(hot["reasons"])!r}, expected exactly '
        "{'TableWriteKeyRangeThroughputExceeded'} -- a table-level reason here means the limiter "
        'is not partition-aware'
    )
    assert hot['resources'] == {arn}, (
        f'ThrottlingReasons named resources {sorted(hot["resources"])!r}, expected exactly the '
        f'table ARN {arn!r}'
    )
    assert hot['landed'] <= 0.70 * dist['landed'], (
        f'the hot arm landed {hot["landed"]} writes against the distributed arm\'s '
        f'{dist["landed"]} of the same offered {_TARGET}/s -- a single partition key must be '
        f'capped far below the table budget'
    )

    # Negative space: exactly the accepted writes landed, and nothing reported unprocessed did.
    hot_count = _count_pk(rd, table, 'hot')
    assert hot_count == hot['landed'], (
        f'a consistent COUNT under pk="hot" found {hot_count} items but the service accepted '
        f'{hot["landed"]} ({hot["accepted"]} batched + {hot["probe_accepted"]} probed) -- a '
        f'throttled write must leave nothing behind, and an accepted one must not be lost'
    )
    absent_probe = sorted(hot['unprocessed_sks'])[:500]
    assert len(absent_probe) == 500, (
        f'only {len(absent_probe)} unprocessed sort keys were captured, needed 500 to probe for '
        f'absence ({hot["unprocessed"]} unprocessed reported)'
    )
    found_rejected = set()
    for i in range(0, len(absent_probe), 100):
        request = {table: {'Keys': [{'pk': {'S': 'hot'}, 'sk': {'S': s}}
                                    for s in absent_probe[i:i + 100]],
                           'ConsistentRead': True, 'ProjectionExpression': 'sk'}}
        while request:
            page = rd.batch_get_item(RequestItems=request)
            found_rejected |= {it['sk']['S'] for it in page['Responses'][table]}
            request = page.get('UnprocessedKeys') or None
    assert found_rejected == set(), (
        f'{len(found_rejected)} items reported as UnprocessedItems are present on a consistent '
        f'read, e.g. {sorted(found_rejected)[:3]!r} -- a throttled write partially landed'
    )

    keys = [f'd{i}' for i in range(_DIST_KEYS)]
    with ThreadPoolExecutor(max_workers=8) as ex:
        per_key = dict(zip(keys, ex.map(lambda k: _count_pk(rd, table, k), keys)))
    batch_share = dist['offered'] // _DIST_KEYS
    thin = {k: n for k, n in per_key.items() if n < batch_share}
    assert thin == {}, (
        f'{len(thin)} of {_DIST_KEYS} distributed keys hold fewer than the {batch_share} items '
        f'the arm wrote to each, e.g. {sorted(thin.items())[:3]!r} -- the load was not actually '
        f'distributed the way the arm intended'
    )
    assert sum(per_key.values()) == warm['landed'] + dist['landed'], (
        f'the {_DIST_KEYS} distributed keys hold {sum(per_key.values())} items but the warm-up '
        f'and the distributed arm together accepted {warm["landed"] + dist["landed"]} -- the '
        f'table lost or duplicated writes'
    )

    # Continuity arm: four keys throttle less than one key, at the same offered rate.
    assert four['unprocessed'] < hot['unprocessed'], (
        f'spreading the same {four["offered"]} writes over 4 partition keys left '
        f'{four["unprocessed"]} unprocessed against {hot["unprocessed"]} for a single key -- the '
        f'limiter is not tracking key cardinality continuously'
    )
    assert four['landed'] > hot['landed'], (
        f'4 keys landed {four["landed"]} writes and 1 key landed {hot["landed"]} of the same '
        f'offered load -- more distinct partition keys must buy more throughput'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
