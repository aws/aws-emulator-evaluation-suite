"""add-notification-channels-grows-and-shrinks."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "add-notification-channels-grows-and-shrinks"
GROUP = "state"
SERVICES = ["codeguruprofiler"]


def _channels(cgp, name):
    return cgp.get_notification_configuration(profilingGroupName=name).get(
        "notificationConfiguration", {}
    ).get("channels", [])


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A profiling group's notification channel list grows one add at a time (up
    to the max of two) and shrinks one remove at a time back to empty."""
    cgp = ctx.client("codeguruprofiler")
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-cgp-")
    cgp.create_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    initial = _channels(cgp, name)
    assert initial == [], f"expected no channels on a fresh profiling group, got {initial!r}"

    topic1 = ctx.unique_name("sim2real-behav-topic-")
    topic2 = ctx.unique_name("sim2real-behav-topic-")
    uri1 = sns.create_topic(Name=topic1, Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=uri1))
    uri2 = sns.create_topic(Name=topic2, Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=uri2))

    resp = cgp.add_notification_channels(
        profilingGroupName=name,
        channels=[{"uri": uri1, "eventPublishers": ["AnomalyDetection"]}],
    )
    channels = resp["notificationConfiguration"]["channels"]
    assert len(channels) == 1, f"expected 1 channel after first add, got {len(channels)}"
    assert channels[0]["uri"] == uri1, f"expected uri {uri1}, got {channels[0]['uri']}"
    channel1_id = channels[0]["id"]

    resp = cgp.add_notification_channels(
        profilingGroupName=name,
        channels=[{"uri": uri2, "eventPublishers": ["AnomalyDetection"]}],
    )
    channels = resp["notificationConfiguration"]["channels"]
    assert len(channels) == 2, f"expected 2 channels after second add, got {len(channels)}"
    uris = {c["uri"] for c in channels}
    assert uris == {uri1, uri2}, f"expected uris {{{uri1}, {uri2}}}, got {uris}"
    channel2_id = next(c["id"] for c in channels if c["uri"] == uri2)

    resp = cgp.remove_notification_channel(profilingGroupName=name, channelId=channel1_id)
    channels = resp["notificationConfiguration"]["channels"]
    assert len(channels) == 1, f"expected 1 channel after removing channel1, got {len(channels)}"
    assert channels[0]["uri"] == uri2, f"expected remaining uri {uri2}, got {channels[0]['uri']}"

    resp = cgp.remove_notification_channel(profilingGroupName=name, channelId=channel2_id)
    channels = resp.get("notificationConfiguration", {}).get("channels", [])
    assert channels == [], f"expected no channels in remove response, got {channels!r}"
    final = _channels(cgp, name)
    assert final == [], f"expected no channels via independent read after both removes, got {final!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
