"""publish-to-deleted-topic-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-to-deleted-topic-not-found"
GROUP = 'error-semantics'
SERVICES = ['sns']

def _create_topic(client, ctx, name, attributes=None, tags=None):
    """CreateTopic + register best-effort DeleteTopic cleanup; returns the TopicArn."""
    kwargs = {"Name": name}
    if attributes:
        kwargs["Attributes"] = attributes
    if tags:
        kwargs["Tags"] = tags
    arn = client.create_topic(**kwargs)["TopicArn"]
    ctx.on_cleanup(lambda: client.delete_topic(TopicArn=arn))
    return arn

def _error(fn):
    """Call fn(); return the botocore error (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _topic_exists(client, arn):
    """True while GetTopicAttributes still answers for arn; False once it reports NotFound."""
    try:
        client.get_topic_attributes(TopicArn=arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NotFound":
            return False
        raise
    return True

def _wait_for_topic_gone(client, arn, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if not _topic_exists(client, arn):
            return
        time.sleep(interval_s)
    raise AssertionError(f"topic {arn} never became NotFound within {timeout_s}s")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Publish to a deleted (nonexistent) TopicArn raises NotFound; the deleted topic
    never reappears in ListTopics, and a live control topic still accepts Publish."""
    ev = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-pubgone-")
    arn = _create_topic(ev, ctx, name)
    ev.delete_topic(TopicArn=arn)
    _wait_for_topic_gone(ev, arn)

    code, message = _error(lambda: ev.publish(TopicArn=arn, Message='ghost'))
    assert code == "NotFound", f"expected NotFound publishing to deleted topic, got {code}"
    assert message == 'Topic does not exist', (
        f"expected the exact message 'Topic does not exist', got {message!r}"
    )

    all_arns = set()
    paginator = ev.get_paginator("list_topics")
    for page in paginator.paginate():
        all_arns.update(t.get("TopicArn") for t in page.get("Topics", []))
    assert arn not in all_arns, f"deleted topic {arn} still present in ListTopics"

    # Positive control: Publish still succeeds against a live topic, so the NotFound
    # above is specific to the deleted topic rather than Publish being broken outright.
    live_arn = _create_topic(ev, ctx, ctx.unique_name("sim2real-behav-sns-pubgone-live-"))
    message_id = ev.publish(TopicArn=live_arn, Message='alive')["MessageId"]
    assert message_id, "expected a MessageId from Publish against a live topic"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
