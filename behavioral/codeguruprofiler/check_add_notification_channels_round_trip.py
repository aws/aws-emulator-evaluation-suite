"""add-notification-channels-round-trip."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "add-notification-channels-round-trip"
GROUP = "notifications"
SERVICES = ["codeguruprofiler"]


def _create_topic(ctx, sns, suffix):
    topic_name = ctx.unique_name("sim2real-cgp-topic-" + suffix + "-")
    topic_arn = sns.create_topic(
        Name=topic_name, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    return topic_arn


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddNotificationChannels grows notificationConfiguration.channels one call at a
    time, and GetNotificationConfiguration reflects the final set of channels."""
    cgp = ctx.client("codeguruprofiler")
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-cgp-notif-")
    token = str(uuid.uuid4())
    cgp.create_profiling_group(
        profilingGroupName=name, clientToken=token, tags={"sim2real": CHECK}
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    topic_1 = _create_topic(ctx, sns, "a")
    topic_2 = _create_topic(ctx, sns, "b")

    add1 = cgp.add_notification_channels(
        profilingGroupName=name,
        channels=[{"uri": topic_1, "eventPublishers": ["AnomalyDetection"]}],
    )
    channels_after_1 = add1["notificationConfiguration"]["channels"]
    assert len(channels_after_1) == 1, f"expected 1 channel after first add, got {channels_after_1}"
    assert channels_after_1[0]["uri"] == topic_1, (
        f"expected channel uri {topic_1}, got {channels_after_1[0]['uri']}"
    )

    add2 = cgp.add_notification_channels(
        profilingGroupName=name,
        channels=[{"uri": topic_2, "eventPublishers": ["AnomalyDetection"]}],
    )
    channels_after_2 = add2["notificationConfiguration"]["channels"]
    assert len(channels_after_2) == 2, f"expected 2 channels after second add, got {channels_after_2}"
    uris = {c["uri"] for c in channels_after_2}
    assert uris == {topic_1, topic_2}, f"expected uris {{{topic_1}, {topic_2}}}, got {uris}"

    fetched = cgp.get_notification_configuration(profilingGroupName=name)
    fetched_uris = {c["uri"] for c in fetched["notificationConfiguration"]["channels"]}
    assert fetched_uris == {topic_1, topic_2}, (
        f"GetNotificationConfiguration expected {{{topic_1}, {topic_2}}}, got {fetched_uris}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
