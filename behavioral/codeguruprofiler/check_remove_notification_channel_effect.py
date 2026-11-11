"""remove-notification-channel-effect."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "remove-notification-channel-effect"
GROUP = "notifications"
SERVICES = ["codeguruprofiler"]


def _mgmt_tags():
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-cgp-rmnotif"}


def _create_topic(ctx, sns, suffix):
    topic_name = ctx.unique_name("sim2real-cgp-topic-" + suffix + "-")
    topic_arn = sns.create_topic(
        Name=topic_name,
        Tags=[{"Key": k, "Value": v} for k, v in _mgmt_tags().items()],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    return topic_arn


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RemoveNotificationChannel removes exactly the targeted channel, leaving the
    other channel intact in the notification configuration."""
    cgp = ctx.client("codeguruprofiler")
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-cgp-rmnotif-")
    token = str(uuid.uuid4())
    cgp.create_profiling_group(
        profilingGroupName=name, clientToken=token, tags=_mgmt_tags()
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    topic_1 = _create_topic(ctx, sns, "a")
    topic_2 = _create_topic(ctx, sns, "b")

    add1 = cgp.add_notification_channels(
        profilingGroupName=name,
        channels=[{"uri": topic_1, "eventPublishers": ["AnomalyDetection"]}],
    )
    channel_1_id = add1["notificationConfiguration"]["channels"][0]["id"]

    add2 = cgp.add_notification_channels(
        profilingGroupName=name,
        channels=[{"uri": topic_2, "eventPublishers": ["AnomalyDetection"]}],
    )
    channel_2 = next(
        c for c in add2["notificationConfiguration"]["channels"] if c["uri"] == topic_2
    )

    cgp.remove_notification_channel(profilingGroupName=name, channelId=channel_1_id)

    remaining = cgp.get_notification_configuration(profilingGroupName=name)
    remaining_channels = remaining["notificationConfiguration"]["channels"]
    assert len(remaining_channels) == 1, (
        f"expected exactly 1 remaining channel after removing channel_1, "
        f"got {remaining_channels!r}"
    )
    assert remaining_channels[0]["id"] == channel_2["id"], (
        f"remaining channel id must be channel_2's id, "
        f"expected {channel_2['id']!r}, got {remaining_channels[0]['id']!r}"
    )
    assert remaining_channels[0]["uri"] == topic_2, (
        f"remaining channel uri must be topic_2, "
        f"expected {topic_2!r}, got {remaining_channels[0]['uri']!r}"
    )
    assert remaining_channels[0] == channel_2, (
        f"untouched channel must read back byte-identical to what AddNotificationChannels "
        f"reported (including eventPublishers), expected {channel_2!r}, "
        f"got {remaining_channels[0]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
