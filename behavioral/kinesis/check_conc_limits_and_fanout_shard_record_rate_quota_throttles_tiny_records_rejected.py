"""conc-limits-and-fanout-shard-record-rate-quota-throttles-tiny-records-rejected."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-limits-and-fanout-shard-record-rate-quota-throttles-tiny-records-rejected"
GROUP = 'limits_rejected'
SERVICES = ['kinesis']

_PRODUCERS = 16         # concurrent sustained PutRecords writers
_PER_CALL = 500         # the documented PutRecords entry maximum
_RECORD_BYTES = 16      # data + partition key stay tiny: the byte quota is never in play
_CODE = 'ProvisionedThroughputExceededException'
# Documented per-shard write quota: 1,000 records/s AND 1 MiB/s. Sixteen concurrent calls of 500
# records are ~136 KB in flight, far under the byte quota, so any throttle is the RECORD-count
# limit. A shard's burst credit lets sustained load reach ~2,100 records/s before entries are
# refused, so no rate number is asserted below.
_BYTE_QUOTA = 1024 * 1024


def _tag(i, j, burst):
    return f'p{i:02d}r{j:06d}'.ljust(_RECORD_BYTES, '.')


def _read_all(k, stream, shard_id, want_tags, budget_s=120):
    """Read TRIM_HORIZON to the tip and return every tag read.

    The read quota (5 GetRecords/s/shard) is respected by a bounded backoff.
    """
    it = k.get_shard_iterator(StreamName=stream, ShardId=shard_id,
                              ShardIteratorType='TRIM_HORIZON')['ShardIterator']
    got = []
    deadline = time.time() + budget_s
    while it and time.time() < deadline:
        try:
            page = k.get_records(ShardIterator=it, Limit=10000)
        except ClientError as exc:
            if exc.response['Error']['Code'] != _CODE:
                raise
            time.sleep(1)
            continue
        got.extend(r['Data'].decode() for r in page['Records'])
        it = page.get('NextShardIterator')
        if page.get('MillisBehindLatest', 1) == 0 and not page['Records'] \
                and want_tags <= set(got):
            break
        time.sleep(0.25)
    return got


def _list_shards(k, stream, timeout_s=60.0):
    """ListShards, retrying ResourceInUseException every 2 s: right after DescribeStream reads ACTIVE,
    ListShards can still see the stream as CREATING."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return k.list_shards(StreamName=stream)['Shards']
        except ClientError as exc:
            if exc.response['Error']['Code'] != 'ResourceInUseException' or time.monotonic() >= deadline:
                raise
        time.sleep(2)


@tags('axis:rejection', 'cap:c2', 'concern:data-plane', 'concern:negative-classes',
      'dp:api', 'plane:data')
def run(ctx) -> None:
    """One shard enforces its record-count write quota independently of the byte quota.

    Sustained tiny-record PutRecords are partially refused with ProvisionedThroughputExceeded;
    refused entries are absent from the shard and the shard holds exactly the acknowledged ones.
    """
    k = ctx.client('kinesis')
    # Retries OFF: the unit under test is the first answer the shard gives each entry.
    kp = ctx.client('kinesis', config=Config(retries={'total_max_attempts': 1},
                                             max_pool_connections=_PRODUCERS + 2))
    assert kp.meta.config.retries['total_max_attempts'] == 1

    stream = ctx.unique_name('sim2real-conc-rate-')
    k.create_stream(StreamName=stream, ShardCount=1,
                    StreamModeDetails={'StreamMode': 'PROVISIONED'})
    ctx.on_cleanup(lambda: k.delete_stream(StreamName=stream, EnforceConsumerDeletion=True))
    k.get_waiter('stream_exists').wait(StreamName=stream,
                                       WaiterConfig={'Delay': 2, 'MaxAttempts': 90})
    k.add_tags_to_stream(StreamName=stream, Tags={'sim2real': CHECK})
    shards = _list_shards(k, stream)
    assert len(shards) == 1, f'a ShardCount=1 stream has {len(shards)} shards'
    shard_id = shards[0]['ShardId']

    # A three-record batch well inside both quotas is accepted in full.
    ctl_tags = [f'ctl{i}'.ljust(_RECORD_BYTES, '.') for i in range(3)]
    ctl = kp.put_records(StreamName=stream, Records=[
        {'Data': t.encode(), 'PartitionKey': 'k'} for t in ctl_tags])
    assert ctl['FailedRecordCount'] == 0, f'control batch refused entries: {ctl["Records"]!r}'

    accepted, refused, codes = set(ctl_tags), set(), set()
    call_bytes = _PER_CALL * (_RECORD_BYTES + 1)
    assert _PRODUCERS * call_bytes < _BYTE_QUOTA // 4, (
        f'{_PRODUCERS} concurrent calls of {call_bytes} bytes would bring the byte quota into play'
    )

    stop = threading.Event()
    deadline = time.time() + 45

    def _producer(i):
        """Call PutRecords until any producer sees a refusal (plus one more call) or time runs out.

        Burst credit absorbs single bursts, so the load must be sustained to trip the quota.
        """
        out, n, extra = [], 0, 1
        while time.time() < deadline:
            if stop.is_set():
                if extra == 0:
                    break
                extra -= 1
            entries = [{'Data': _tag(i, n + j, 0).encode(), 'PartitionKey': 'k'}
                       for j in range(_PER_CALL)]
            n += _PER_CALL
            resp = kp.put_records(StreamName=stream, Records=entries)
            assert len(resp['Records']) == len(entries), (
                f'PutRecords returned {len(resp["Records"])} results for {len(entries)} entries'
            )
            batch = [(e['Data'].decode(), r.get('SequenceNumber'), r.get('ErrorCode'),
                      r.get('ErrorMessage')) for e, r in zip(entries, resp['Records'])]
            assert resp['FailedRecordCount'] == sum(1 for _, _, c, _ in batch if c), (
                f'FailedRecordCount {resp["FailedRecordCount"]} disagrees with the per-entry '
                f'ErrorCodes'
            )
            if resp['FailedRecordCount']:
                stop.set()
            out.extend(batch)
        return out

    with ThreadPoolExecutor(max_workers=_PRODUCERS) as pool:
        results = list(pool.map(_producer, range(_PRODUCERS)))
    for out in results:
        for t, seq, code, message in out:
            if code:
                assert not seq, f'refused entry {t!r} also carries SequenceNumber {seq!r}'
                refused.add(t)
                codes.add((code, message))
            else:
                assert seq, f'accepted entry {t!r} carries no SequenceNumber'
                accepted.add(t)

    assert refused, (
        f'{_PRODUCERS} producers writing {_PER_CALL}-record calls back to back for 45s never '
        f"exceeded one shard's record-count write quota -- the limit is not enforced"
    )
    want_error = (
        _CODE, f'Rate exceeded for shard {shard_id} in stream {stream} under account {ctx.account}.'
    )
    assert codes == {want_error}, (
        f'refused entries carried (ErrorCode, ErrorMessage) {sorted(codes)!r}, '
        f'expected exactly {{{want_error!r}}}'
    )
    assert len(accepted) > len(ctl_tags), 'no burst entry was accepted at all'

    read = _read_all(k, stream, shard_id, accepted)
    read_set = set(read)
    missing = accepted - read_set
    assert not missing, (
        f'{len(missing)} acknowledged records are not readable from the shard, e.g. '
        f'{sorted(missing)[:5]!r}'
    )
    ghosts = refused & read_set
    assert not ghosts, (
        f'{len(ghosts)} entries refused with {_CODE} were stored anyway, e.g. '
        f'{sorted(ghosts)[:5]!r}'
    )
    assert read_set == accepted, (
        f'the shard holds {len(read_set - accepted)} records that were never acknowledged'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
