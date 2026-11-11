"""delete-configuration-set-cascades-event-destinations."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-configuration-set-cascades-event-destinations"
GROUP = "lifecycle"
SERVICES = ["pinpoint-sms-voice-v2", "sns"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting a configuration set deletes its attached event destination too, rather
    than leaving an orphan a direct lookup would still find.
    """
    client = ctx.client("pinpoint-sms-voice-v2")
    sns = ctx.client("sns")

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-topic-"))["TopicArn"]
    ctx.on_cleanup(_teardown(lambda: sns.delete_topic(TopicArn=topic_arn), "NotFound"))

    name = ctx.unique_name("sim2real-behav-cfgset-")
    client.create_configuration_set(ConfigurationSetName=name)
    ctx.on_cleanup(
        _teardown(
            lambda: client.delete_configuration_set(ConfigurationSetName=name),
            "ResourceNotFoundException",
        )
    )

    evd_name = ctx.unique_name("sim2real-behav-evd-")
    client.create_event_destination(
        ConfigurationSetName=name,
        EventDestinationName=evd_name,
        MatchingEventTypes=["TEXT_ALL"],
        SnsDestination={"TopicArn": topic_arn},
    )

    before = client.describe_configuration_sets(ConfigurationSetNames=[name])["ConfigurationSets"][
        0
    ]
    assert [e["EventDestinationName"] for e in before["EventDestinations"]] == [evd_name], (
        f"expected exactly {evd_name!r} attached before delete, got {before['EventDestinations']!r}"
    )

    client.delete_configuration_set(ConfigurationSetName=name)

    expected_message = f'Resource Not Found - ResourceType="configuration-set" ResourceId="{name}"'

    code, message = _error(lambda: client.describe_configuration_sets(ConfigurationSetNames=[name]))
    assert code == "ResourceNotFoundException", (
        f"configuration set describe gave {code!r} after delete"
    )
    assert message == expected_message, f"unexpected message {message!r}"

    # The cascade must be real, not just unobservable through the parent: the event
    # destination's own delete call must also find nothing left to delete.
    code, message = _error(
        lambda: client.delete_event_destination(
            ConfigurationSetName=name,
            EventDestinationName=evd_name,
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected the cascaded event destination to already be gone, got {code!r}"
    )
    assert message == expected_message, f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
