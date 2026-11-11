"""add-notification-channels-duplicate-uri-tolerated."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "add-notification-channels-duplicate-uri-tolerated"
GROUP = "notifications"
SERVICES = ["codeguruprofiler"]


def _channels(cgp, name):
    return (
        cgp.get_notification_configuration(profilingGroupName=name)
        .get("notificationConfiguration", {})
        .get("channels", [])
    )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddNotificationChannels called again with a uri that already has a
    channel is idempotent (no ConflictException, no duplicate entry created);
    adding a channel with a distinct URI still succeeds and grows the set."""
    cgp = ctx.client("codeguruprofiler")
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-cgp-")
    cgp.create_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"env": "sim2real-test"},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    topic_x = ctx.unique_name("sim2real-behav-topic-")
    topic_y = ctx.unique_name("sim2real-behav-topic-")
    tag_kv = [{"Key": "sim2real", "Value": "add-notification-channels-duplicate-uri-tolerated"}]
    uri_x = sns.create_topic(Name=topic_x, Tags=tag_kv)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=uri_x))
    uri_y = sns.create_topic(Name=topic_y, Tags=tag_kv)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=uri_y))

    first_resp = cgp.add_notification_channels(
        profilingGroupName=name,
        channels=[{"uri": uri_x, "eventPublishers": ["AnomalyDetection"]}],
    )
    first_channels = first_resp["notificationConfiguration"]["channels"]
    assert [c["uri"] for c in first_channels] == [uri_x], first_channels

    # Re-adding the same URI is idempotent: no error, no duplicate entry.
    # (Real AWS was measured to assign a fresh channel id on the re-add, not
    # preserve the original one, so the id itself is not asserted here.)
    dup_resp = cgp.add_notification_channels(
        profilingGroupName=name,
        channels=[{"uri": uri_x, "eventPublishers": ["AnomalyDetection"]}],
    )
    dup_channels = dup_resp["notificationConfiguration"]["channels"]
    assert len(dup_channels) == 1, dup_channels
    assert dup_channels[0]["uri"] == uri_x, (uri_x, dup_channels[0]["uri"])

    channels = _channels(cgp, name)
    assert len(channels) == 1, channels
    assert channels[0]["uri"] == uri_x, (uri_x, channels[0]["uri"])

    # Positive control: adding a channel with a distinct URI succeeds.
    cgp.add_notification_channels(
        profilingGroupName=name,
        channels=[{"uri": uri_y, "eventPublishers": ["AnomalyDetection"]}],
    )
    final = {c["uri"] for c in _channels(cgp, name)}
    assert final == {uri_x, uri_y}, (uri_x, uri_y, final)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
