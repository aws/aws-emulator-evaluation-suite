"""protect-configuration-association-independent-of-event-destinations."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "protect-configuration-association-independent-of-event-destinations"
GROUP = "orthogonality"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A configuration set's protect-configuration association survives an unrelated
    mutation (adding then removing an event destination) on the same resource.
    """
    client = ctx.client("pinpoint-sms-voice-v2")
    sns = ctx.client("sns")

    name = ctx.unique_name("sim2real-behav-cfgset-")
    client.create_configuration_set(ConfigurationSetName=name)
    ctx.on_cleanup(
        _teardown(
            lambda: client.delete_configuration_set(ConfigurationSetName=name),
            "ResourceNotFoundException",
        )
    )

    pc = client.create_protect_configuration()
    pc_id = pc["ProtectConfigurationId"]
    assert pc["AccountDefault"] is False, (
        f"a freshly created protect configuration must not be AccountDefault, got {pc!r}"
    )
    ctx.on_cleanup(
        _teardown(
            lambda: client.delete_protect_configuration(ProtectConfigurationId=pc_id),
            "ResourceNotFoundException",
        )
    )

    client.associate_protect_configuration(ProtectConfigurationId=pc_id, ConfigurationSetName=name)

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-topic-"))["TopicArn"]
    ctx.on_cleanup(_teardown(lambda: sns.delete_topic(TopicArn=topic_arn), "NotFound"))
    evd_name = ctx.unique_name("sim2real-behav-evd-")
    client.create_event_destination(
        ConfigurationSetName=name,
        EventDestinationName=evd_name,
        MatchingEventTypes=["TEXT_ALL"],
        SnsDestination={"TopicArn": topic_arn},
    )

    described = client.describe_configuration_sets(ConfigurationSetNames=[name])[
        "ConfigurationSets"
    ][0]
    assert described["ProtectConfigurationId"] == pc_id, (
        f"adding an event destination must not touch the protect-configuration association, "
        f"expected {pc_id!r}, got {described.get('ProtectConfigurationId')!r}"
    )

    client.delete_event_destination(ConfigurationSetName=name, EventDestinationName=evd_name)

    described = client.describe_configuration_sets(ConfigurationSetNames=[name])[
        "ConfigurationSets"
    ][0]
    assert described["ProtectConfigurationId"] == pc_id, (
        f"removing the event destination must not touch the protect-configuration association, "
        f"expected {pc_id!r}, got {described.get('ProtectConfigurationId')!r}"
    )
    assert described["EventDestinations"] == [], (
        f"expected no event destinations left, got {described['EventDestinations']!r}"
    )

    # A protect configuration refuses deletion while still associated with a
    # configuration set, so the association must end before cleanup deletes either side.
    client.disassociate_protect_configuration(
        ProtectConfigurationId=pc_id, ConfigurationSetName=name
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
