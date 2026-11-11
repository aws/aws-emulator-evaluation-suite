"""add-notification-channels-invalid-event-publisher-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-notification-channels-invalid-event-publisher-rejected"
GROUP = "overly-permissive"
SERVICES = ["codeguruprofiler"]


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ValidationException, but the call SUCCEEDED and returned {result!r}")


def _create_topic(ctx, sns, suffix):
    topic_name = ctx.unique_name("sim2real-cgp-topic-" + suffix + "-")
    topic_arn = sns.create_topic(Name=topic_name)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    return topic_arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddNotificationChannels rejects an eventPublishers value other than AnomalyDetection with
    ValidationException and its exact message, leaving no channels, while a valid call for another URI adds
    exactly that channel.
    """
    cgp = ctx.client("codeguruprofiler")
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-cgp-dupuri-")
    token = str(uuid.uuid4())
    cgp.create_profiling_group(profilingGroupName=name, clientToken=token)
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    topic_1 = _create_topic(ctx, sns, "a")
    topic_2 = _create_topic(ctx, sns, "b")

    code, message = _error_code(
        lambda: cgp.add_notification_channels(
            profilingGroupName=name,
            channels=[{"uri": topic_1, "eventPublishers": ["NotARealPublisher"]}],
        )
    )
    assert code == "ValidationException", (code, message)
    expected_message = (
        "1 validation error detected: Value '[NotARealPublisher]' at "
        "'channels.1.member.eventPublishers' failed to satisfy constraint: Member must "
        "satisfy constraint: [Member must satisfy enum value set: [AnomalyDetection]]"
    )
    assert message == expected_message, (message, expected_message)

    # effect absent: no channel was created for the rejected request
    after_reject = cgp.get_notification_configuration(profilingGroupName=name)
    assert after_reject["notificationConfiguration"]["channels"] == [], (
        f"expected no channel after the rejected call, got "
        f"{after_reject['notificationConfiguration']['channels']!r}"
    )

    # positive control: the valid enum value for a distinct URI still succeeds
    cgp.add_notification_channels(
        profilingGroupName=name,
        channels=[{"uri": topic_2, "eventPublishers": ["AnomalyDetection"]}],
    )

    # terminal read: independent of the mutating add_notification_channels call
    after_accept = cgp.get_notification_configuration(profilingGroupName=name)
    uris = {c["uri"] for c in after_accept["notificationConfiguration"]["channels"]}
    assert uris == {topic_2}, f"expected only {topic_2!r} on an independent read, got {uris!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
