"""remove-notification-channel-unknown-channel-not-found-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "remove-notification-channel-unknown-channel-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["codeguruprofiler"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RemoveNotificationChannel with a well-formed channelId not on the group fails with ValidationException and
    its exact message, leaving the real channel, while removing the real channel by its id succeeds.
    """
    cgp = ctx.client("codeguruprofiler")
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-cgp-")
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))
    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-cgp-sns-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    cgp.create_profiling_group(profilingGroupName=name)
    added = cgp.add_notification_channels(
        profilingGroupName=name,
        channels=[{"uri": topic_arn, "eventPublishers": ["AnomalyDetection"]}],
    )
    real_channel_id = added["notificationConfiguration"]["channels"][0]["id"]

    unknown_channel_id = str(uuid.uuid4())
    code, message = _error(
        lambda: cgp.remove_notification_channel(
            profilingGroupName=name, channelId=unknown_channel_id
        )
    )
    assert code == "ValidationException", code
    expected = (
        f"Channel not found with channelId: {unknown_channel_id}, profilingGroupName: {name} "
        f"and AccountId: {ctx.account}"
    )
    assert message == expected, f"message {message!r}, expected {expected!r}"

    unchanged = cgp.get_notification_configuration(profilingGroupName=name)
    assert [c["id"] for c in unchanged["notificationConfiguration"]["channels"]] == [
        real_channel_id
    ]

    cgp.remove_notification_channel(profilingGroupName=name, channelId=real_channel_id)
    after = cgp.get_notification_configuration(profilingGroupName=name)
    assert after["notificationConfiguration"].get("channels", []) == []


def _error(fn):
    """The error code and message *fn* raises; a call that succeeds fails the check."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("the call succeeded; real AWS rejects it")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
