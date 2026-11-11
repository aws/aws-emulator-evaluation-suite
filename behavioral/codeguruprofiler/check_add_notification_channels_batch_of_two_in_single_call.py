"""add-notification-channels-batch-of-two-in-single-call."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-notification-channels-batch-of-two-in-single-call"
GROUP = "notifications"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With one channel slot left, AddNotificationChannels with two channels fails with
    ServiceQuotaExceededException and adds neither; on an empty group the same two-channel call adds both, as
    GetNotificationConfiguration confirms.
    """
    cgp = ctx.client("codeguruprofiler")
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-cgp-")
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))
    topic1_arn = sns.create_topic(Name=ctx.unique_name("sim2real-cgp-sns-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic1_arn))
    topic2_arn = sns.create_topic(Name=ctx.unique_name("sim2real-cgp-sns-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic2_arn))
    topic3_arn = sns.create_topic(Name=ctx.unique_name("sim2real-cgp-sns-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic3_arn))

    cgp.create_profiling_group(profilingGroupName=name)

    # Fill one of the two slots, so the batch of two below has only one slot free.
    filler = cgp.add_notification_channels(
        profilingGroupName=name,
        channels=[{"uri": topic1_arn, "eventPublishers": ["AnomalyDetection"]}],
    )
    filler_id = filler["notificationConfiguration"]["channels"][0]["id"]

    # Break exactly one thing: submit a batch of two when only one slot remains.
    code, message = _error_code(
        lambda: cgp.add_notification_channels(
            profilingGroupName=name,
            channels=[
                {"uri": topic2_arn, "eventPublishers": ["AnomalyDetection"]},
                {"uri": topic3_arn, "eventPublishers": ["AnomalyDetection"]},
            ],
        )
    )
    assert code == "ServiceQuotaExceededException", (code, message)
    expected_message = "Channel limit exceeded: Only 2 channels allowed per profiling group"
    assert message == expected_message, (message, expected_message)

    # Effect absent: the rejected batch added neither channel, not even the one that
    # would have fit in the single free slot.
    after_reject = cgp.get_notification_configuration(profilingGroupName=name)
    after_uris = {c["uri"] for c in after_reject["notificationConfiguration"]["channels"]}
    assert after_uris == {topic1_arn}, after_uris

    # Restore: free the slot, then the identical batch call succeeds atomically.
    cgp.remove_notification_channel(profilingGroupName=name, channelId=filler_id)

    added = cgp.add_notification_channels(
        profilingGroupName=name,
        channels=[
            {"uri": topic2_arn, "eventPublishers": ["AnomalyDetection"]},
            {"uri": topic3_arn, "eventPublishers": ["AnomalyDetection"]},
        ],
    )
    added_uris = {c["uri"] for c in added["notificationConfiguration"]["channels"]}
    assert added_uris == {topic2_arn, topic3_arn}, added_uris

    fetched = cgp.get_notification_configuration(profilingGroupName=name)
    fetched_uris = {c["uri"] for c in fetched["notificationConfiguration"]["channels"]}
    assert fetched_uris == {topic2_arn, topic3_arn}, fetched_uris


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
