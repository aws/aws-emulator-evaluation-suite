"""add-notification-channels-channel-id-auto-assigned-uuid."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "add-notification-channels-channel-id-auto-assigned-uuid"
GROUP = "state"
SERVICES = ["codeguruprofiler"]

_UUID_RE = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """When a channel is added without an explicit id, the server auto-assigns
    a random UUID-shaped channelId, and an independent GetNotificationConfiguration
    read reflects the same durably-stored id."""
    cgp = ctx.client("codeguruprofiler")
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-cgp-")
    cgp.create_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"sim2real-audit": "true"},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    topic_name = ctx.unique_name("sim2real-behav-topic-")
    uri = sns.create_topic(
        Name=topic_name, Tags=[{"Key": "sim2real-audit", "Value": "true"}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=uri))

    resp = cgp.add_notification_channels(
        profilingGroupName=name,
        channels=[{"uri": uri, "eventPublishers": ["AnomalyDetection"]}],
    )
    channels = resp["notificationConfiguration"]["channels"]
    assert len(channels) == 1, f"expected 1 channel in mutation response, got {channels}"
    mutation_id = channels[0]["id"]
    assert _UUID_RE.match(mutation_id) is not None, (
        f"expected UUID-shaped channelId, got {mutation_id!r}"
    )

    fetched = cgp.get_notification_configuration(profilingGroupName=name)
    fetched_channels = fetched["notificationConfiguration"]["channels"]
    assert len(fetched_channels) == 1, (
        f"expected 1 channel on independent read, got {fetched_channels}"
    )
    fetched_id = fetched_channels[0]["id"]
    assert fetched_id == mutation_id, (
        f"independent read id {fetched_id!r} != mutation response id {mutation_id!r}"
    )
    assert _UUID_RE.match(fetched_id) is not None, (
        f"expected UUID-shaped channelId on independent read, got {fetched_id!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
