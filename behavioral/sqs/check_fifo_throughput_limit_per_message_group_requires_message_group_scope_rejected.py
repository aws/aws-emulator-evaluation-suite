"""fifo-throughput-limit-per-message-group-requires-message-group-scope-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fifo-throughput-limit-per-message-group-requires-message-group-scope-rejected"
GROUP = 'fifo'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "fifo-ht-combination"}

_COMBO_MESSAGE = (
    "Invalid value for the parameter FifoThroughputLimit. Reason: To set FifoThroughputLimit to "
    "perMessageGroupId, the DeduplicationScope must be messageGroup."
)
_HT = {"DeduplicationScope": "messageGroup", "FifoThroughputLimit": "perMessageGroupId"}
_NORMAL = {"DeduplicationScope": "queue", "FifoThroughputLimit": "perQueue"}
# Bound on how long the scope change may take to govern deduplication.
_CONVERGE_S = 90.0


def _error(fn):
    """(code, message) of the refusal ``fn`` raises; an unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _ht_attrs(sqs, url):
    return sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["DeduplicationScope", "FifoThroughputLimit"])["Attributes"]


def _same_id_two_groups(sqs, url, dedup_id):
    """Send one dedup id to two groups; True when the second send was deduplicated."""
    a = sqs.send_message(QueueUrl=url, MessageBody=f"g1-{dedup_id}", MessageGroupId="g1",
                         MessageDeduplicationId=dedup_id)["MessageId"]
    b = sqs.send_message(QueueUrl=url, MessageBody=f"g2-{dedup_id}", MessageGroupId="g2",
                         MessageDeduplicationId=dedup_id)["MessageId"]
    return a == b


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:control", "plane:data")
def run(ctx) -> None:
    """FifoThroughputLimit=perMessageGroupId requires DeduplicationScope=messageGroup.

    Illegal pairings are refused and change nothing; changing both together moves dedup queue-wide.
    """
    sqs = ctx.client("sqs")
    token = uuid.uuid4().hex[:8]

    bad_name = ctx.unique_name("sim2real-behav-") + "-bad.fifo"
    code, msg = _error(lambda: sqs.create_queue(
        QueueName=bad_name, tags=_TAGS, Attributes={
            "FifoQueue": "true", "DeduplicationScope": "queue",
            "FifoThroughputLimit": "perMessageGroupId"}))
    assert (code, msg) == ("InvalidAttributeValue", _COMBO_MESSAGE), (
        f"illegal CreateQueue gave {(code, msg)!r}")
    code, msg = _error(lambda: sqs.get_queue_url(QueueName=bad_name))
    assert (code, msg) == ("AWS.SimpleQueueService.NonExistentQueue",
                   "The specified queue does not exist."), (
        f"the refused CreateQueue left a resolvable queue behind: GetQueueUrl gave {(code, msg)!r}")

    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + ".fifo", tags=_TAGS,
        Attributes={"FifoQueue": "true", **_HT})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    assert _ht_attrs(sqs, url) == _HT, f"high-throughput queue read back {_ht_attrs(sqs, url)!r}"

    code, msg = _error(lambda: sqs.set_queue_attributes(
        QueueUrl=url, Attributes={"DeduplicationScope": "queue"}))
    assert (code, msg) == ("InvalidAttributeValue", _COMBO_MESSAGE), (
        f"scope-only downgrade gave {(code, msg)!r}")
    stored = _ht_attrs(sqs, url)
    assert stored == _HT, f"the refused update changed the stored attributes: {stored!r}"
    assert not _same_id_two_groups(sqs, url, f"kept-{token}"), (
        "after the refused update a repeated dedup id in a second group was collapsed; "
        "deduplication must still be per message group")

    sqs.set_queue_attributes(QueueUrl=url, Attributes=_NORMAL)
    stored = _ht_attrs(sqs, url)
    assert stored == _NORMAL, f"the accepted downgrade read back {stored!r}"
    collapsed = None
    deadline = time.monotonic() + _CONVERGE_S
    n = 0
    while collapsed is None and time.monotonic() < deadline:
        dedup_id = f"queue-wide-{n}-{token}"
        n += 1
        if _same_id_two_groups(sqs, url, dedup_id):
            collapsed = dedup_id
        else:
            time.sleep(2)
    assert collapsed is not None, (
        f"{_CONVERGE_S:.0f}s after DeduplicationScope=queue a repeated dedup id in a second "
        f"group was still delivered separately ({n} attempts)")

    bodies: list[str] = []
    empties = 0
    deadline = time.monotonic() + 60
    while empties < 3 and time.monotonic() < deadline:
        batch = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                    WaitTimeSeconds=2).get("Messages", [])
        empties = 0 if batch else empties + 1
        for m in batch:
            bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    assert f"g1-kept-{token}" in bodies and f"g2-kept-{token}" in bodies, (
        f"per-group dedup kept both sends of the repeated id, so both must be delivered: "
        f"{sorted(bodies)!r}")
    assert f"g1-{collapsed}" in bodies and f"g2-{collapsed}" not in bodies, (
        f"queue-wide dedup must deliver the first send of {collapsed!r} only: {sorted(bodies)!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
