"""notification-channel-add-remove-lifecycle."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "notification-channel-add-remove-lifecycle"
GROUP = "notification"
SERVICES = ["codeguruprofiler"]


def _error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddNotificationChannels attaches an SNS channel with an assigned id that GetNotificationConfiguration
    returns, RemoveNotificationChannel detaches it, and removing the same id again fails with
    ValidationException and its exact message.
    """
    cgp = ctx.client("codeguruprofiler")
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-cgp-")
    topic_name = ctx.unique_name("sim2real-cgp-topic-")

    cgp.create_profiling_group(profilingGroupName=name, clientToken=str(uuid.uuid4()))
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    topic_arn = sns.create_topic(Name=topic_name)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    add_resp = cgp.add_notification_channels(
        profilingGroupName=name,
        channels=[{"uri": topic_arn, "eventPublishers": ["AnomalyDetection"]}],
    )
    channels = add_resp["notificationConfiguration"]["channels"]
    assert len(channels) == 1, channels
    assert channels[0]["uri"] == topic_arn, channels[0]
    assert channels[0]["eventPublishers"] == ["AnomalyDetection"], channels[0]
    channel_id = channels[0]["id"]
    assert channel_id, channels[0]

    got = cgp.get_notification_configuration(profilingGroupName=name)["notificationConfiguration"]
    assert [c["id"] for c in got["channels"]] == [channel_id], got["channels"]

    remove_resp = cgp.remove_notification_channel(profilingGroupName=name, channelId=channel_id)
    remaining = remove_resp["notificationConfiguration"].get("channels", [])
    assert remaining == [], remaining

    got_after = cgp.get_notification_configuration(profilingGroupName=name)[
        "notificationConfiguration"
    ]
    assert got_after.get("channels", []) == [], got_after

    # The removed channelId is dead: a second removal of the same id must be
    # rejected rather than silently succeeding (which would mean the first removal
    # never actually took effect on the server's own bookkeeping). Real AWS rejects
    # an unknown channelId as a validation failure on the request, not as a
    # resource-not-found -- the profiling group itself still exists.
    err = _error(
        lambda: cgp.remove_notification_channel(profilingGroupName=name, channelId=channel_id)
    )
    assert err["Code"] == "ValidationException", err
    expected = (
        f"Channel not found with channelId: {channel_id}, profilingGroupName: {name} "
        f"and AccountId: {ctx.account}"
    )
    assert err["Message"] == expected, (err["Message"], expected)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
