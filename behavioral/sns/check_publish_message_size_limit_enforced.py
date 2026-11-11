"""publish-message-size-limit-enforced."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-message-size-limit-enforced"
GROUP = 'overly-permissive'
SERVICES = ['sns']

def _create_topic(client, ctx, name, attributes=None):
    """CreateTopic (tagged so a leftover can be found) + register DeleteTopic cleanup; returns the TopicArn."""
    arn = client.create_topic(
        Name=name,
        Attributes=attributes or {},
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: client.delete_topic(TopicArn=arn))
    return arn

@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Publish must reject a message larger than the 256 KB (262144 byte) payload limit."""
    ev = ctx.client("sns")
    topic_arn = _create_topic(ev, ctx, ctx.unique_name("sim2real-behav-sns-toobig-"))
    oversized = "x" * (262144 + 1024)
    try:
        ev.publish(TopicArn=topic_arn, Message=oversized)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(
            "a Publish over the 262144-byte limit was expected to be rejected, but it SUCCEEDED"
        )
    assert code == "InvalidParameter", (
        f"expected InvalidParameter for message over the 256KB limit, got {code}"
    )
    assert message == 'Invalid parameter: Message too long', (
        f"expected the exact message 'Invalid parameter: Message too long', got {message!r}"
    )
    # Effect absent / control: the topic still accepts a legal publish afterwards, so the
    # rejection was about size and not about the topic being poisoned by it. This is also the
    # independent terminal read: a target that returned InvalidParameter for every publish,
    # oversized or not, must fail here.
    ok = "y" * (262144 - 1024)
    resp = ev.publish(TopicArn=topic_arn, Message=ok)
    assert resp.get("MessageId"), (
        f"expected a {len(ok)}-byte publish (under the 262144-byte limit) to be accepted after "
        f"the rejection, got {resp}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
