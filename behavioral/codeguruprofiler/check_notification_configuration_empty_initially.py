"""notification-configuration-empty-initially."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "notification-configuration-empty-initially"
GROUP = "notification"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created profiling group has no notification channels until
    AddNotificationChannels is called."""
    cgp = ctx.client("codeguruprofiler")
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-cgp-")

    cgp.create_profiling_group(profilingGroupName=name, clientToken=str(uuid.uuid4()))
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    config = cgp.get_notification_configuration(profilingGroupName=name)[
        "notificationConfiguration"
    ]
    assert config.get("channels", []) == [], (
        f"expected no channels on a freshly created profiling group, got {config.get('channels')!r}"
    )

    # Positive control on the same wiring: without this, a target with no
    # notification-channel delivery path at all scores an empty result too.
    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-cgp-topic-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    added = cgp.add_notification_channels(
        profilingGroupName=name,
        channels=[{"uri": topic_arn, "eventPublishers": ["AnomalyDetection"]}],
    )["notificationConfiguration"]["channels"]
    assert len(added) == 1, f"expected AddNotificationChannels to add exactly 1 channel, got {added!r}"
    assert added[0]["uri"] == topic_arn, (
        f"expected the added channel's uri to be {topic_arn!r}, got {added[0].get('uri')!r}"
    )

    refetched = cgp.get_notification_configuration(profilingGroupName=name)[
        "notificationConfiguration"
    ]["channels"]
    assert [c["uri"] for c in refetched] == [topic_arn], (
        f"expected GetNotificationConfiguration to reflect the added channel "
        f"{topic_arn!r}, got {refetched!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
