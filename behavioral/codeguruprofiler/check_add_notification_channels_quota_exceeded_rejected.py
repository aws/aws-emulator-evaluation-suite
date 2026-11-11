"""add-notification-channels-quota-exceeded-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-notification-channels-quota-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["codeguruprofiler"]


def _error_code(fn):
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A third AddNotificationChannels on a group with two channels fails with ServiceQuotaExceededException and
    its exact message, leaving both channels, and freeing a slot lets the same add succeed.
    """
    cgp = ctx.client("codeguruprofiler")
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-cgp-")
    cgp.create_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    def _topic(suffix):
        arn = sns.create_topic(
            Name=ctx.unique_name(f"sim2real-behav-topic-{suffix}-"),
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["TopicArn"]
        ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
        return arn

    uri1, uri2, uri3 = _topic("a"), _topic("b"), _topic("c")

    cgp.add_notification_channels(
        profilingGroupName=name,
        channels=[{"uri": uri1, "eventPublishers": ["AnomalyDetection"]}],
    )
    cgp.add_notification_channels(
        profilingGroupName=name,
        channels=[{"uri": uri2, "eventPublishers": ["AnomalyDetection"]}],
    )
    grown = {c["uri"] for c in _channels(cgp, name)}
    assert grown == {uri1, uri2}, f"expected {{uri1, uri2}} after two adds, got {grown}"

    # Break exactly one thing: try to add a third channel while already at the max.
    code, message = _error_code(
        lambda: cgp.add_notification_channels(
            profilingGroupName=name,
            channels=[{"uri": uri3, "eventPublishers": ["AnomalyDetection"]}],
        )
    )
    assert code == "ServiceQuotaExceededException", (
        f"expected ServiceQuotaExceededException for a third channel at the max of two, got {code}"
    )
    expected_message = "Channel limit exceeded: Only 2 channels allowed per profiling group"
    assert message == expected_message, (message, expected_message)

    # Effect absent: still exactly the original two channels, uri3 was not added.
    channels = _channels(cgp, name)
    unaffected = {c["uri"] for c in channels}
    assert unaffected == {uri1, uri2}, (
        f"expected the rejected add to leave {{uri1, uri2}} untouched, got {unaffected}"
    )

    # Positive control: freeing a slot lets the same add succeed.
    channel1_id = next(c["id"] for c in channels if c["uri"] == uri1)
    cgp.remove_notification_channel(profilingGroupName=name, channelId=channel1_id)
    cgp.add_notification_channels(
        profilingGroupName=name,
        channels=[{"uri": uri3, "eventPublishers": ["AnomalyDetection"]}],
    )
    restored = {c["uri"] for c in _channels(cgp, name)}
    assert restored == {uri2, uri3}, (
        f"expected freeing a slot to let the identical add succeed, got {restored}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
