"""add-notification-channels-duplicate-uri-and-quota-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-notification-channels-duplicate-uri-and-quota-rejected"
GROUP = "overly-permissive"
SERVICES = ["codeguruprofiler"]


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _channels(cgp, name):
    return (
        cgp.get_notification_configuration(profilingGroupName=name)
        .get("notificationConfiguration", {})
        .get("channels", [])
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """At two channels, re-adding an existing URI succeeds without using quota (the other channel keeps its id),
    a new third URI fails with ServiceQuotaExceededException leaving both channels, and freeing a slot lets
    the add succeed.
    """
    cgp = ctx.client("codeguruprofiler")
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-cgp-dupquota-")
    cgp.create_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    def _topic(suffix):
        arn = sns.create_topic(
            Name=ctx.unique_name(f"sim2real-cgp-dupquota-{suffix}-"),
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["TopicArn"]
        ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
        return arn

    topic1, topic2, topic3 = _topic("a"), _topic("b"), _topic("c")

    added1 = cgp.add_notification_channels(
        profilingGroupName=name,
        channels=[{"uri": topic1, "eventPublishers": ["AnomalyDetection"]}],
    )
    channel1_id = added1["notificationConfiguration"]["channels"][0]["id"]

    added2 = cgp.add_notification_channels(
        profilingGroupName=name,
        channels=[{"uri": topic2, "eventPublishers": ["AnomalyDetection"]}],
    )
    at_max_channels = added2["notificationConfiguration"]["channels"]
    at_max = {c["uri"] for c in at_max_channels}
    assert at_max == {topic1, topic2}, f"expected {{topic1, topic2}} at the max of two, got {at_max}"
    channel2_id = next(c["id"] for c in at_max_channels if c["uri"] == topic2)

    # At the max, re-adding an existing uri is still idempotent -- it does not
    # count against the quota (still exactly two channels) and the untouched
    # channel (topic2) keeps its id, but the re-added channel (topic1) is
    # issued a freshly generated id.
    dup_result = cgp.add_notification_channels(
        profilingGroupName=name,
        channels=[{"uri": topic1, "eventPublishers": ["AnomalyDetection"]}],
    )
    dup_channels = dup_result["notificationConfiguration"]["channels"]
    dup_ids = {c["uri"]: c["id"] for c in dup_channels}
    assert set(dup_ids) == {topic1, topic2}, (
        f"expected exactly {{topic1, topic2}} after the duplicate add, got {set(dup_ids)}"
    )
    assert dup_ids[topic2] == channel2_id, (
        f"expected the untouched channel (topic2) to keep id {channel2_id}, got {dup_ids[topic2]}"
    )
    assert dup_ids[topic1] != channel1_id, (
        f"expected the re-added channel (topic1) to be issued a fresh id, "
        f"but it kept its original id {channel1_id}"
    )
    current_channel1_id = dup_ids[topic1]

    # A genuinely new third uri is rejected at the max, even though the
    # duplicate add above just succeeded.
    code, message = _error(
        lambda: cgp.add_notification_channels(
            profilingGroupName=name,
            channels=[{"uri": topic3, "eventPublishers": ["AnomalyDetection"]}],
        )
    )
    assert code == "ServiceQuotaExceededException", (
        f"expected ServiceQuotaExceededException for a third distinct uri at the max, got {code}"
    )
    expected = "Channel limit exceeded: Only 2 channels allowed per profiling group"
    assert message == expected, (
        f"third distinct uri at the max: message {message!r}, expected {expected!r}"
    )

    # Effect absent: still exactly the current two channels, with their
    # current ids, untouched by the rejected add.
    unaffected = {c["uri"]: c["id"] for c in _channels(cgp, name)}
    assert unaffected == {topic1: current_channel1_id, topic2: channel2_id}, (
        f"expected the rejected add to leave {{topic1: {current_channel1_id}, topic2: {channel2_id}}} "
        f"untouched, got {unaffected}"
    )

    # Positive control: freeing a slot lets the identical add succeed.
    cgp.remove_notification_channel(profilingGroupName=name, channelId=current_channel1_id)
    cgp.add_notification_channels(
        profilingGroupName=name,
        channels=[{"uri": topic3, "eventPublishers": ["AnomalyDetection"]}],
    )
    restored = {c["uri"] for c in _channels(cgp, name)}
    assert restored == {topic2, topic3}, (
        f"expected freeing a slot to let the identical add succeed, got {restored}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
