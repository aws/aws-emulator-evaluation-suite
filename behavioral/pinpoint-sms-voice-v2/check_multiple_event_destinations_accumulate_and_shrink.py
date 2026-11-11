"""multiple-event-destinations-accumulate-and-shrink."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "multiple-event-destinations-accumulate-and-shrink"
GROUP = "accumulated-state"
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


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A configuration set's EventDestinations accumulates every destination created on
    it and reflects exactly the surviving set after one of several is deleted.
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

    evd_names = []
    for i in range(3):
        topic_arn = sns.create_topic(Name=ctx.unique_name(f"sim2real-behav-topic-{i}-"))["TopicArn"]
        ctx.on_cleanup(_teardown(lambda arn=topic_arn: sns.delete_topic(TopicArn=arn), "NotFound"))
        evd_name = ctx.unique_name(f"sim2real-behav-evd-{i}-")
        client.create_event_destination(
            ConfigurationSetName=name,
            EventDestinationName=evd_name,
            MatchingEventTypes=["TEXT_ALL"],
            SnsDestination={"TopicArn": topic_arn},
        )
        evd_names.append(evd_name)

    described = client.describe_configuration_sets(ConfigurationSetNames=[name])[
        "ConfigurationSets"
    ][0]
    seen = {e["EventDestinationName"] for e in described["EventDestinations"]}
    assert seen == set(evd_names), (
        f"expected all three destinations {evd_names!r}, got {sorted(seen)!r}"
    )

    removed = evd_names[1]
    client.delete_event_destination(ConfigurationSetName=name, EventDestinationName=removed)

    described = client.describe_configuration_sets(ConfigurationSetNames=[name])[
        "ConfigurationSets"
    ][0]
    seen = {e["EventDestinationName"] for e in described["EventDestinations"]}
    remaining = set(evd_names) - {removed}
    assert seen == remaining, (
        f"after deleting {removed!r} expected {sorted(remaining)!r} to remain, got {sorted(seen)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
