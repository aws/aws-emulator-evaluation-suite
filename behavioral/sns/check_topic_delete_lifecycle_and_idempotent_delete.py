"""topic-delete-lifecycle-and-idempotent-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-delete-lifecycle-and-idempotent-delete"
GROUP = 'topic-lifecycle'
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

def _get_topic_attributes_error(client, arn):
    """(Code, Message) of the refused GetTopicAttributes. An unexpected SUCCESS raises."""
    try:
        result = client.get_topic_attributes(TopicArn=arn)
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"GetTopicAttributes on deleted topic {arn} SUCCEEDED: {result!r}")

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting a topic removes it (GetTopicAttributes -> NotFound); redeleting is a no-op that
    leaves the topic exactly as gone."""
    ev = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-del-")
    arn = _create_topic(ev, ctx, name)
    ev.get_topic_attributes(TopicArn=arn)
    ev.delete_topic(TopicArn=arn)
    code, message = _get_topic_attributes_error(ev, arn)
    assert code == "NotFound", f"expected NotFound after delete, got {code}"
    assert message == "Topic does not exist", f"unexpected NotFound message after delete: {message!r}"
    redelete = ev.delete_topic(TopicArn=arn)
    redelete_status = redelete.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert redelete_status == 200, (
        f"expected redeleting an already-deleted topic to be a no-op (200), got {redelete_status}"
    )
    code_after_redelete, message_after_redelete = _get_topic_attributes_error(ev, arn)
    assert code_after_redelete == "NotFound", (
        f"expected topic to remain gone (NotFound) after idempotent redelete, got {code_after_redelete}"
    )
    assert message_after_redelete == "Topic does not exist", (
        f"unexpected NotFound message after idempotent redelete: {message_after_redelete!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
