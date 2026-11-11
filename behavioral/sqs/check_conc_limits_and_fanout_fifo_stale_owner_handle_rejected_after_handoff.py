"""conc-limits-and-fanout-fifo-stale-owner-handle-rejected-after-handoff."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-limits-and-fanout-fifo-stale-owner-handle-rejected-after-handoff"
GROUP = 'concurrency_rejected'
SERVICES = ['sqs']

_N = 5
_HANDOFF = 3
_VT = 300


def _error(fn):
    """Return the botocore Error dict of fn(). An unexpected SUCCESS raises: an emulator
    accepting a call real AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {})
    raise AssertionError(f'expected a refusal, but the call SUCCEEDED and returned {result!r}')


def _receive_exact(sqs, url, want, budget_s=30):
    got = {}
    deadline = time.time() + budget_s
    while len(got) < want and time.time() < deadline:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2,
                                     AttributeNames=['ApproximateReceiveCount']
                                     ).get('Messages', []):
            assert m['MessageId'] not in got, (
                f'message {m["Body"]!r} was handed out twice to one receiver inside its window'
            )
            got[m['MessageId']] = m
    return got


@tags('axis:rejection', 'cap:c2', 'concern:data-plane', 'concern:negative-classes',
      'dp:api', 'plane:data')
def run(ctx) -> None:
    """On FIFO, after receiver B takes a message A released, A's stale handle is refused for
    DeleteMessage and ChangeMessageVisibility with no effect; A's current handles still work.
    """
    sqs_a = ctx.client('sqs')   # receiver A
    sqs_b = ctx.client('sqs')   # receiver B -- a separate client, a separate consumer
    # FIFO only: on a standard queue a stale-handle DeleteMessage can succeed and remove the
    # message from under B, contradicting the DeleteMessage docs, so that arm is not asserted.
    name = ctx.unique_name('sim2real-conc-handoff-')[:75] + '.fifo'
    url = sqs_a.create_queue(QueueName=name, Attributes={
        'FifoQueue': 'true', 'VisibilityTimeout': str(_VT)},
        tags={'sim2real': CHECK})['QueueUrl']
    ctx.on_cleanup(lambda: sqs_a.delete_queue(QueueUrl=url))

    resp = sqs_a.send_message_batch(QueueUrl=url, Entries=[
        {'Id': f'e{i}', 'MessageBody': f'm{i}', 'MessageGroupId': f'g{i}',
         'MessageDeduplicationId': f'd{i}'} for i in range(_N)])
    assert not resp.get('Failed'), f'send_message_batch failures: {resp["Failed"]!r}'
    sent = {s['MessageId'] for s in resp['Successful']}

    a_got = _receive_exact(sqs_a, url, _N)
    assert set(a_got) == sent, (
        f'receiver A collected {sorted(m["Body"] for m in a_got.values())!r}, expected all {_N}'
    )
    ordered = sorted(a_got)
    handed = ordered[:_HANDOFF]
    kept = ordered[_HANDOFF:]

    # Hand three to B: A releases them, B receives exactly those three.
    for mid in handed:
        sqs_a.change_message_visibility(QueueUrl=url, ReceiptHandle=a_got[mid]['ReceiptHandle'],
                                        VisibilityTimeout=0)
    b_got = _receive_exact(sqs_b, url, _HANDOFF)
    assert set(b_got) == set(handed), (
        f'receiver B got {sorted(m["Body"] for m in b_got.values())!r}; expected exactly the '
        f'{_HANDOFF} released messages {sorted(a_got[m]["Body"] for m in handed)!r}'
    )
    assert {int(m['Attributes']['ApproximateReceiveCount']) for m in b_got.values()} == {2}

    # The refusal: A's stale handles for B's messages.
    for mid in handed:
        stale = a_got[mid]['ReceiptHandle']
        expected_message = (f'Value {stale} for parameter ReceiptHandle is invalid. '
                            f'Reason: The receipt handle has expired.')
        err = _error(lambda: sqs_a.delete_message(QueueUrl=url, ReceiptHandle=stale))
        assert err.get('Code') == 'InvalidParameterValue', (
            f'stale-owner DeleteMessage on {a_got[mid]["Body"]!r} was refused with '
            f'{err.get("Code")!r}, expected InvalidParameterValue ({err!r})'
        )
        assert err.get('Message') == expected_message, (
            f'stale-owner refusal message {err.get("Message")!r}, expected {expected_message!r}'
        )
        err = _error(lambda: sqs_a.change_message_visibility(
            QueueUrl=url, ReceiptHandle=stale, VisibilityTimeout=0))
        assert err.get('Code') == 'InvalidParameterValue', (
            f'stale-owner ChangeMessageVisibility on {a_got[mid]["Body"]!r} was refused with '
            f'{err.get("Code")!r}, expected InvalidParameterValue ({err!r})'
        )
        assert err.get('Message') == expected_message, (
            f'stale-owner refusal message {err.get("Message")!r}, expected {expected_message!r}'
        )

    # A's current handles for the two it still owns work, and delete for real.
    for mid in kept:
        sqs_a.delete_message(QueueUrl=url, ReceiptHandle=a_got[mid]['ReceiptHandle'])

    # B still owns all three, so a receive now returns none of them...
    early = _receive_exact(sqs_a, url, 1, budget_s=6)
    assert early == {}, (
        f'after A\'s refused stale-handle calls, {sorted(m["Body"] for m in early.values())!r} '
        f'became receivable while B still owned it'
    )
    # ...and when B releases them, exactly those three come back, received a third time.
    for mid, m in b_got.items():
        sqs_b.change_message_visibility(QueueUrl=url, ReceiptHandle=m['ReceiptHandle'],
                                        VisibilityTimeout=0)
    again = _receive_exact(sqs_b, url, _HANDOFF)
    assert set(again) == set(handed), (
        f'after B released its messages, a receive returned '
        f'{sorted(m["Body"] for m in again.values())!r}; expected exactly the three handed-off '
        f'messages -- a stale delete must not have removed any, and A\'s real deletes must hold'
    )
    assert {int(m['Attributes']['ApproximateReceiveCount']) for m in again.values()} == {3}, (
        f'receive counts {sorted(int(m["Attributes"]["ApproximateReceiveCount"]) for m in again.values())!r}'
        f', expected 3 for each'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
