"""topic-create-idempotent-by-name."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "topic-create-idempotent-by-name"
GROUP = 'topic-lifecycle'
SERVICES = ['sns']

_SCENARIO = "sns-topic-create-idempotent-by-name"


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]


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

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTopic with an existing Name is idempotent and returns the same ARN."""
    ev = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-idem-")
    arn1 = _create_topic(ev, ctx, name, tags=_tags_kv())
    resp2 = ev.create_topic(Name=name)
    arn2 = resp2["TopicArn"]
    assert arn1 == arn2, f"expected same TopicArn on repeat create, got {arn1} vs {arn2}"
    topics = [t for page in ev.get_paginator("list_topics").paginate() for t in page["Topics"]]
    matches = [t for t in topics if t["TopicArn"] == arn1]
    assert len(matches) == 1, f"expected exactly one topic for {name}, found {len(matches)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
