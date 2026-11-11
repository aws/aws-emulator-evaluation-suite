"""conc-limits-and-fanout-in-flight-disjoint-and-cmv-zero-redelivers-exact-subset."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "conc-limits-and-fanout-in-flight-disjoint-and-cmv-zero-redelivers-exact-subset"
GROUP = 'concurrency'
SERVICES = ['sqs']

_N = 30            # messages, one MessageGroupId each
_RECEIVERS = 6     # concurrent receivers
_VT = 600          # queue VisibilityTimeout, seconds -- the window every "hidden" claim lives in
_RESET = 7         # messages whose visibility is reset to 0
_BATCH = 2         # MaxNumberOfMessages per receive during a drain


@tags("cap:c2", "concern:data-plane", "dp:api", "plane:data", "axis:happy-path")
def run(ctx) -> None:
    """Six concurrent receivers on a FIFO queue get disjoint messages covering all 30; in-flight
    ones stay hidden, and visibility 0 on seven redelivers exactly those seven (receive count 2).
    """
    sqs = ctx.client('sqs')
    # FIFO because standard queues are at-least-once (disjointness is not guaranteed); one group
    # per message avoids FIFO head-of-line blocking.
    name = ctx.unique_name('sim2real-conc-inflight-')[:75] + '.fifo'
    url = sqs.create_queue(QueueName=name, Attributes={
        'FifoQueue': 'true', 'VisibilityTimeout': str(_VT)},
        tags={'sim2real': CHECK})['QueueUrl']
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    sent = {}
    for base in range(0, _N, 10):
        entries = [{'Id': f'e{i}', 'MessageBody': f'm{i}', 'MessageGroupId': f'g{i}',
                    'MessageDeduplicationId': f'd{i}'} for i in range(base, min(base + 10, _N))]
        resp = sqs.send_message_batch(QueueUrl=url, Entries=entries)
        assert not resp.get('Failed'), f'send_message_batch reported failures: {resp["Failed"]!r}'
        for ok in resp['Successful']:
            sent[ok['MessageId']] = ok['Id']
    assert len(sent) == _N, f'{len(sent)} distinct MessageIds acknowledged for {_N} sends'

    lock = threading.Lock()
    first_receive = []

    def _drain(target, budget_s):
        """Concurrent receivers until `target` distinct messages have been collected or the
        budget ends. Returns every (receiver, MessageId, ReceiptHandle, ReceiveCount) seen."""
        seen = []
        stop = time.time() + budget_s
        # Every receiver starts together, and each call takes at most _BATCH, so the drain needs
        # many overlapping calls rather than one fast receiver taking the whole queue.
        start = threading.Barrier(_RECEIVERS)

        def _receiver(r):
            mine = []
            start.wait(timeout=30)
            while time.time() < stop:
                with lock:
                    if len({s[1] for s in seen}) >= target:
                        break
                got = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=_BATCH, WaitTimeSeconds=1,
                                          AttributeNames=['ApproximateReceiveCount']
                                          ).get('Messages', [])
                with lock:
                    if got and not first_receive:
                        first_receive.append(time.time())
                    for m in got:
                        rec = (r, m['MessageId'], m['ReceiptHandle'],
                               int(m['Attributes']['ApproximateReceiveCount']))
                        seen.append(rec)
                        mine.append(rec)
            return mine
        with ThreadPoolExecutor(max_workers=_RECEIVERS) as pool:
            list(pool.map(_receiver, range(_RECEIVERS)))
        return seen

    def _still_inside_window(label):
        elapsed = time.time() - first_receive[0]
        assert elapsed < _VT - 60, (
            f'{label}: {elapsed:.0f}s have passed since the first receive, too close to the '
            f'{_VT}s visibility window for a "still hidden" claim to be meaningful'
        )

    def _empty_round():
        with ThreadPoolExecutor(max_workers=_RECEIVERS) as pool:
            batches = list(pool.map(lambda _: sqs.receive_message(
                QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get('Messages', []),
                range(_RECEIVERS)))
        return [m['MessageId'] for b in batches for m in b]

    # Round 1: concurrent drain of the whole queue.
    round1 = _drain(_N, budget_s=90)
    ids1 = [s[1] for s in round1]
    dupes = sorted({i for i in ids1 if ids1.count(i) > 1})
    assert not dupes, (
        f'{len(dupes)} messages were handed to more than one receive inside the visibility '
        f'window: {[sent.get(d) for d in dupes]!r}'
    )
    assert set(ids1) == set(sent), (
        f'the concurrent drain collected {len(set(ids1))} of {_N}; missing '
        f'{sorted(sent[i] for i in set(sent) - set(ids1))!r}, unknown '
        f'{sorted(set(ids1) - set(sent))!r}'
    )
    per_receiver = {s[0] for s in round1}
    assert len(per_receiver) >= 2, (
        f'only receiver(s) {sorted(per_receiver)!r} got anything -- the drain was not concurrent, '
        f'so disjointness was never exercised'
    )
    assert {s[3] for s in round1} == {1}, (
        f'first-round ApproximateReceiveCount values {sorted({s[3] for s in round1})!r}, expected 1'
    )

    # Everything is in flight: a further concurrent round returns nothing.
    _still_inside_window('after round 1')
    leaked = _empty_round()
    assert leaked == [], (
        f'with all {_N} messages in flight, concurrent receives still returned '
        f'{[sent.get(i) for i in leaked]!r}'
    )

    # Reset visibility on exactly seven, spread across whichever receivers got them.
    handles = {s[1]: s[2] for s in round1}
    subset = sorted(handles)[:_RESET]
    for mid in subset:
        sqs.change_message_visibility(QueueUrl=url, ReceiptHandle=handles[mid],
                                      VisibilityTimeout=0)

    round2 = _drain(_RESET, budget_s=60)
    ids2 = [s[1] for s in round2]
    dupes2 = sorted({i for i in ids2 if ids2.count(i) > 1})
    assert not dupes2, f'reset messages delivered twice in round 2: {[sent[d] for d in dupes2]!r}'
    assert set(ids2) == set(subset), (
        f'after resetting visibility on {sorted(sent[i] for i in subset)!r}, round 2 returned '
        f'{sorted(sent.get(i, i) for i in ids2)!r}; expected exactly the reset subset'
    )
    counts = {sent[s[1]]: s[3] for s in round2}
    assert set(counts.values()) == {2}, (
        f'redelivered messages report ApproximateReceiveCount {counts!r}; each was received '
        f'exactly twice'
    )

    # The complement is still hidden, and so is the subset now that round 2 holds it.
    _still_inside_window('after round 2')
    leaked2 = _empty_round()
    assert leaked2 == [], (
        f'after round 2 every message is in flight again, yet concurrent receives returned '
        f'{[sent.get(i) for i in leaked2]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
