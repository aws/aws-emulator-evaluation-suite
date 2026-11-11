"""publish-non-bmp-message-attribute-value-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "publish-non-bmp-message-attribute-value-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sns']

_SCENARIO = "sns-non-bmp-attribute"

# U+1F680 ROCKET: an astral-plane (non-BMP) codepoint, i.e. a surrogate pair in UTF-16.
_ASTRAL = "\U0001F680"
# The same idea inside the BMP: multi-byte in UTF-8, single UTF-16 code unit.
_BMP = "日本語"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """Publish with an astral-plane codepoint in a String message-attribute value is refused
    InvalidParameter and not delivered; the same codepoint in the body is delivered verbatim.
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(ctx)
    queue_url, queue_arn = _create_queue_for_topic(ctx, topic_arn)
    _subscribe_and_confirm(ctx, topic_arn, queue_arn)

    rejected_marker = ctx.unique_name("sim2real-behav-sns-astral-rejected-")
    control_marker = ctx.unique_name("sim2real-behav-sns-astral-control-")
    control_body = f"{control_marker} {_ASTRAL}"

    # The documented attribute charset (XML Char) includes #x10000-#x10FFFF, yet Publish refuses it.
    code = _error_code(lambda: sns.publish(
        TopicArn=topic_arn,
        Message=rejected_marker,
        MessageAttributes={"tag": {"DataType": "String", "StringValue": f"ok-{_ASTRAL}"}},
    ))
    assert code == "InvalidParameter", (
        f"an astral-plane codepoint in a String message-attribute value was not rejected with "
        f"InvalidParameter: {code!r}"
    )

    sns.publish(
        TopicArn=topic_arn,
        Message=control_body,
        MessageAttributes={"tag": {"DataType": "String", "StringValue": f"ok-{_BMP}"}},
    )
    bodies = _drain_until_containing(ctx, queue_url, control_marker, timeout_s=90.0)
    bodies += _receive_any(ctx, queue_url, rounds=1, wait_s=20)

    matched = [b for b in bodies if control_marker in b]
    assert len(matched) == 1, (
        f"expected exactly one control delivery, got {len(matched)}: {[b[:160] for b in bodies]!r}"
    )
    envelope = json.loads(matched[0])
    assert envelope["Message"] == control_body, (
        f"the same astral codepoint is legal in the body and must round-trip verbatim: "
        f"{envelope['Message']!r} != {control_body!r}"
    )
    assert envelope["MessageAttributes"]["tag"]["Value"] == f"ok-{_BMP}", (
        f"the BMP attribute value was mangled, so the control does not isolate the astral case: "
        f"{envelope['MessageAttributes']['tag']!r}"
    )
    assert not any(rejected_marker in b for b in bodies), (
        f"the refused publish was delivered anyway: {[b[:160] for b in bodies]!r}"
    )


def _error_code(fn) -> str:
    """The AWS error Code raised by fn(); raise if fn succeeds."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, returning {result!r}"
    )


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]


def _create_topic(ctx, *, fifo: bool = False, attributes: dict | None = None) -> str:
    """CreateTopic (tagged + prefix-named) and register DeleteTopic immediately; returns the ARN."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-t-")
    attrs = dict(attributes or {})
    if fifo:
        name = name + ".fifo"
        attrs["FifoTopic"] = "true"
    arn = sns.create_topic(Name=name, Attributes=attrs, Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn


def _create_queue_for_topic(ctx, topic_arn: str, *, fifo: bool = False) -> tuple[str, str]:
    """Create a real SQS queue whose policy lets exactly this topic publish to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-q-")
    attrs: dict[str, str] = {}
    if fifo:
        name = name + ".fifo"
        attrs["FifoQueue"] = "true"
    url = sqs.create_queue(
        QueueName=name, Attributes=attrs,
        tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda u=url: ctx.client("sqs").delete_queue(QueueUrl=u))
    arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, arn


def _subscribe_and_confirm(ctx, topic_arn: str, queue_arn: str, *,
                           attributes: dict | None = None, timeout_s: float = 60.0) -> str:
    """Subscribe an SQS queue and poll GetSubscriptionAttributes until it is confirmed."""
    sns = ctx.client("sns")
    kwargs: dict = {"TopicArn": topic_arn, "Protocol": "sqs", "Endpoint": queue_arn,
                    "ReturnSubscriptionArn": True}
    if attributes:
        kwargs["Attributes"] = attributes
    sub_arn = sns.subscribe(**kwargs)["SubscriptionArn"]
    ctx.on_cleanup(lambda s=sub_arn: ctx.client("sns").unsubscribe(SubscriptionArn=s))
    deadline = time.monotonic() + timeout_s
    pending = None
    while time.monotonic() < deadline:
        pending = sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("PendingConfirmation")
        if pending == "false":
            return sub_arn
        time.sleep(1.0)
    raise AssertionError(
        f"subscription {sub_arn!r} was still PendingConfirmation={pending!r} after {timeout_s}s"
    )


def _drain_until_containing(ctx, queue_url: str, needle: str, *,
                            timeout_s: float = 90.0) -> list[str]:
    """Long-poll until a body containing needle arrives; returns every body seen up to and
    including it, so the caller can assert on what else came through."""
    sqs = ctx.client("sqs")
    bodies: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            bodies.append(msg.get("Body", ""))
        if any(needle in b for b in bodies):
            return bodies
    raise AssertionError(
        f"the control publish {needle!r} never arrived within {timeout_s}s, so the absence of the "
        f"refused publish is not bounded; bodies seen: {[b[:160] for b in bodies]!r}"
    )


def _receive_any(ctx, queue_url: str, *, rounds: int, wait_s: int) -> list[str]:
    """Long-poll a queue `rounds` times and return every body it produced (expected: none)."""
    sqs = ctx.client("sqs")
    bodies: list[str] = []
    for _ in range(rounds):
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            bodies.append(msg.get("Body", ""))
    return bodies


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
