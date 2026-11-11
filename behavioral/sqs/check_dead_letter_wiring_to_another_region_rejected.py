"""dead-letter-wiring-to-another-region-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dead-letter-wiring-to-another-region-rejected"
GROUP = "cross-region"
SERVICES = ["sqs"]

_TAGS = {"sim2real": "dead-letter-wiring-to-another-region-rejected"}
_NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"
_SETTLE_S = 60.0


def _other_region(region: str) -> str:
    return "us-east-1" if region != "us-east-1" else "us-west-2"


def _error(fn) -> dict:
    """The botocore Error dict ``fn`` raises. An unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"]


def _delete_quietly(sqs, url: str) -> None:
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != _NO_SUCH_QUEUE:
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A RedrivePolicy or RedriveAllowPolicy naming a queue in another region is refused with
    InvalidParameterValue on SetQueueAttributes and CreateQueue and stores nothing; the same
    documents naming same-region queues are accepted and ListDeadLetterSourceQueues reports them.
    """
    home = ctx.client("sqs")
    alt_region = _other_region(ctx.region)
    alt = ctx.client("sqs", region=alt_region)
    base = ctx.unique_name("sim2real-behav-xr-dlq-")

    src_url = home.create_queue(QueueName=base + "-src", tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_quietly(home, src_url))
    local_dlq = home.create_queue(QueueName=base + "-dlq", tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_quietly(home, local_dlq))
    far_dlq = alt.create_queue(QueueName=base + "-dlq", tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_quietly(alt, far_dlq))
    src_arn, local_arn, far_arn = _arn(home, src_url), _arn(home, local_dlq), _arn(alt, far_dlq)

    far_policy = json.dumps({"deadLetterTargetArn": far_arn, "maxReceiveCount": "3"})
    region_msg = (f"Value {far_policy} for parameter RedrivePolicy is invalid. Reason: "
                  "Dead-letter target must be in same region as the source.")

    err = _error(lambda: home.set_queue_attributes(
        QueueUrl=src_url, Attributes={"RedrivePolicy": far_policy}))
    assert (err.get("Code"), err.get("Message")) == ("InvalidParameterValue", region_msg), (
        f"SetQueueAttributes with a DLQ in {alt_region!r} answered {err!r}"
    )
    attrs = home.get_queue_attributes(QueueUrl=src_url, AttributeNames=["All"])["Attributes"]
    assert "RedrivePolicy" not in attrs, (
        f"the refused cross-region RedrivePolicy was stored anyway: {attrs.get('RedrivePolicy')!r}"
    )

    created_name = base + "-born"
    err = _error(lambda: home.create_queue(
        QueueName=created_name, Attributes={"RedrivePolicy": far_policy}, tags=_TAGS))
    assert (err.get("Code"), err.get("Message")) == ("InvalidParameterValue", region_msg), (
        f"CreateQueue with a DLQ in {alt_region!r} answered {err!r}"
    )
    missing = _error(lambda: home.get_queue_url(QueueName=created_name))
    assert missing.get("Code") == _NO_SUCH_QUEUE, (
        f"the refused CreateQueue left a queue behind: GetQueueUrl answered {missing!r}"
    )

    allow = json.dumps({"redrivePermission": "byQueue", "sourceQueueArns": [far_arn]})
    err = _error(lambda: home.set_queue_attributes(
        QueueUrl=local_dlq, Attributes={"RedriveAllowPolicy": allow}))
    allow_msg = (f"Value {allow} for parameter RedriveAllowPolicy is invalid. Reason: Amazon SQS "
                 "can't create the redrive allow policy. All source queue ARNs must be in the "
                 "same region as the current SQS queue.")
    assert (err.get("Code"), err.get("Message")) == ("InvalidParameterValue", allow_msg), (
        f"RedriveAllowPolicy listing a {alt_region!r} source answered {err!r}"
    )
    dlq_attrs = home.get_queue_attributes(QueueUrl=local_dlq, AttributeNames=["All"])["Attributes"]
    assert "RedriveAllowPolicy" not in dlq_attrs, (
        f"the refused RedriveAllowPolicy was stored: {dlq_attrs.get('RedriveAllowPolicy')!r}"
    )

    # Attribute and source-list reads lag the write, so poll them within _SETTLE_S.
    home.set_queue_attributes(QueueUrl=local_dlq, Attributes={"RedriveAllowPolicy": json.dumps(
        {"redrivePermission": "byQueue", "sourceQueueArns": [src_arn]})})
    home.set_queue_attributes(QueueUrl=src_url, Attributes={"RedrivePolicy": json.dumps(
        {"deadLetterTargetArn": local_arn, "maxReceiveCount": "3"})})
    stored = None
    sources: list[str] = []
    deadline = time.monotonic() + _SETTLE_S
    while time.monotonic() < deadline:
        stored = home.get_queue_attributes(
            QueueUrl=src_url, AttributeNames=["RedrivePolicy"])["Attributes"].get("RedrivePolicy")
        sources = [u for page in home.get_paginator("list_dead_letter_source_queues").paginate(
            QueueUrl=local_dlq) for u in page.get("queueUrls", [])]
        if stored and sources:
            break
        time.sleep(3)
    assert stored and json.loads(stored)["deadLetterTargetArn"] == local_arn, (
        f"the same-region RedrivePolicy reads back as {stored!r}"
    )
    assert sources == [src_url], (
        f"ListDeadLetterSourceQueues for the same-region DLQ lists {len(sources)} source(s), "
        f"expected exactly the source queue"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
