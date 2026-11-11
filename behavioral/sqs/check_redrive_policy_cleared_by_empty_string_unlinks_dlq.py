"""redrive-policy-cleared-by-empty-string-unlinks-dlq."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "redrive-policy-cleared-by-empty-string-unlinks-dlq"
GROUP = 'dlq'
SERVICES = ['sqs']

_TAGS = {"sim2real": "redrive-policy-cleared-by-empty-string-unlinks-dlq"}


def _sources(sqs, dlq_url):
    return sqs.list_dead_letter_source_queues(QueueUrl=dlq_url).get("queueUrls", [])


def _poll(fn, pred, timeout_s=90):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val) and time.monotonic() < deadline:
        time.sleep(2)
        val = fn()
    return val


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Setting RedrivePolicy to "" removes it: the attribute disappears and the DLQ stops listing
    that source in ListDeadLetterSourceQueues, while a sibling source stays listed and re-setting
    the policy links the first source again."""
    sqs = ctx.client("sqs")
    base = ctx.unique_name("sim2real-behav-rpc-")
    dlq_url = sqs.create_queue(QueueName=base + "-dlq", tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(
        QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 5})
    src_a = sqs.create_queue(QueueName=base + "-a", tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_a))
    src_b = sqs.create_queue(QueueName=base + "-b", tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_b))
    for src in (src_a, src_b):
        sqs.set_queue_attributes(QueueUrl=src, Attributes={"RedrivePolicy": policy})

    both = _poll(lambda: sorted(_sources(sqs, dlq_url)), lambda v: v == sorted([src_a, src_b]))
    assert both == sorted([src_a, src_b]), (
        f"with both sources linked the DLQ lists {len(both)} sources, expected 2"
    )

    sqs.set_queue_attributes(QueueUrl=src_a, Attributes={"RedrivePolicy": ""})
    attrs = sqs.get_queue_attributes(
        QueueUrl=src_a, AttributeNames=["RedrivePolicy"]).get("Attributes", {})
    assert "RedrivePolicy" not in attrs, (
        f"after clearing with '' the source still reports RedrivePolicy={attrs.get('RedrivePolicy')!r}"
    )
    kept = sqs.get_queue_attributes(
        QueueUrl=src_b, AttributeNames=["RedrivePolicy"]).get("Attributes", {}).get("RedrivePolicy")
    assert kept is not None and json.loads(kept).get("deadLetterTargetArn") == dlq_arn, (
        "clearing one source's policy disturbed the sibling source's policy"
    )

    only_b = _poll(lambda: _sources(sqs, dlq_url), lambda v: v == [src_b])
    assert only_b == [src_b], (
        f"after unlinking one source the DLQ lists {len(only_b)} sources "
        f"({'including' if src_a in only_b else 'excluding'} the cleared one), expected only the "
        f"sibling"
    )

    sqs.set_queue_attributes(QueueUrl=src_a, Attributes={"RedrivePolicy": policy})
    again = _poll(lambda: sorted(_sources(sqs, dlq_url)), lambda v: v == sorted([src_a, src_b]))
    assert again == sorted([src_a, src_b]), (
        f"re-setting the policy did not relink the source: the DLQ lists {len(again)} sources"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
