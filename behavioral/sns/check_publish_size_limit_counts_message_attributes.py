"""publish-size-limit-counts-message-attributes."""
from __future__ import annotations

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "publish-size-limit-counts-message-attributes"
GROUP = 'publish-semantics'
SERVICES = ['sns']

_MAX_BYTES = 262144   # 256 KB, the SNS published message-size limit


def _create_topic(client, ctx, name, attributes=None):
    """CreateTopic + register best-effort DeleteTopic cleanup; returns the TopicArn."""
    kwargs = {"Name": name}
    if attributes:
        kwargs["Attributes"] = attributes
    kwargs["Tags"] = [{"Key": "sim2real", "Value": "check_publish_size_limit_counts_message_attributes"}]
    arn = client.create_topic(**kwargs)["TopicArn"]
    ctx.on_cleanup(lambda: client.delete_topic(TopicArn=arn))
    return arn


def _err(fn):
    """Call fn(); return the error (Code, Message). An unexpected success raises.

    Only `ClientError` is caught: a client-side `ParamValidationError` never reached the service.
    """
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        f"expected the oversized publish to be rejected, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """The 256 KB Publish limit is counted across the message body AND its attributes: body and
    attribute are each accepted alone but refused together, as are many small attributes.

    Reference: https://docs.aws.amazon.com/sns/latest/api/API_Publish.html
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(sns, ctx, ctx.unique_name("sim2real-behav-sns-sizeattr-"))

    # A body ~8 KB below the limit, and a ~12 KB attribute value. Either alone is legal;
    # together they exceed 256 KB.
    body = "b" * (_MAX_BYTES - 8192)
    attr_value = "a" * 12288
    attrs = {"bulk": {"DataType": "String", "StringValue": attr_value}}

    # Control A: the body alone is under the limit and is accepted.
    resp_a = sns.publish(TopicArn=topic_arn, Message=body)
    assert resp_a.get("MessageId"), (
        f"expected a {len(body)}-byte body (under the {_MAX_BYTES}-byte limit) to be accepted, got {resp_a}"
    )

    # Control B: the same attribute with a tiny body is accepted, so the attribute itself is
    # not independently illegal.
    resp_b = sns.publish(TopicArn=topic_arn, Message="tiny", MessageAttributes=attrs)
    assert resp_b.get("MessageId"), (
        f"expected a {len(attr_value)}-byte attribute with a 4-byte body to be accepted, got {resp_b}"
    )

    # The assertion: body + attribute together exceed 256 KB and must be refused.
    total = len(body) + len(attr_value)
    code, message = _err(lambda: sns.publish(TopicArn=topic_arn, Message=body, MessageAttributes=attrs))
    assert code == "InvalidParameter", (
        f"expected InvalidParameter for a publish totalling ~{total} bytes across body and "
        f"attributes (limit {_MAX_BYTES}); got {code}"
    )
    assert message == 'Invalid parameter: Message too long', (
        f"expected the exact message 'Invalid parameter: Message too long', got {message!r}"
    )

    # Same shape via a second, independent attribute-count path: many small attributes
    # summing over the limit, so an emulator that caps per-attribute size rather than total
    # size is also caught.
    many = {f"k{i:02d}": {"DataType": "String", "StringValue": "c" * 8192} for i in range(40)}
    code_many, message_many = _err(
        lambda: sns.publish(TopicArn=topic_arn, Message="small", MessageAttributes=many))
    assert code_many == "InvalidParameter", (
        "expected InvalidParameter for 40 x 8 KB attributes (~327 KB of attributes) with a "
        f"5-byte body; got {code_many}"
    )
    assert message_many == 'Invalid parameter: Message too long', (
        f"expected the exact message 'Invalid parameter: Message too long', got {message_many!r}"
    )

    # Effect absent / control: the topic still accepts a legal publish, so the rejections
    # were about size and not about the topic being poisoned by them.
    resp_final = sns.publish(TopicArn=topic_arn, Message="after-rejections", MessageAttributes={
        "bulk": {"DataType": "String", "StringValue": "small"},
    })
    assert resp_final.get("MessageId"), (
        f"expected the control publish to still be accepted after the rejections, got {resp_final}"
    )
    assert resp_final["MessageId"] not in (resp_a["MessageId"], resp_b["MessageId"]), (
        "each accepted publish must mint a distinct MessageId; got a repeat of an earlier id"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
