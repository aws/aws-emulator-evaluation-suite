"""event-destination-duplicate-create-and-unknown-update-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-destination-duplicate-create-and-unknown-update-rejected"
GROUP = "event-destinations"
SERVICES = ["sesv2", "sns", "sts"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises, tolerating the resource's own
    not-found codes."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in not_found:
                return
            raise

    return run_undo


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert (got_code, got_message) == (code, message), (
        f"expected ({code!r}, {message!r}), got ({got_code!r}, {got_message!r})"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On one configuration set, recreating an event destination name is refused by
    AlreadyExistsException and updating an unknown one by NotFoundException; neither
    refusal adds, removes or alters the set's one real destination."""
    ses = ctx.client("sesv2")
    sns = ctx.client("sns")
    sts = ctx.client("sts")

    account = sts.get_caller_identity()["Account"]

    cs_name = ctx.unique_name("sim2real-behav-sesv2-cs-")
    ses.create_configuration_set(ConfigurationSetName=cs_name)
    ctx.on_cleanup(_teardown(
        lambda: ses.delete_configuration_set(ConfigurationSetName=cs_name), "NotFoundException"
    ))

    topic_name = ctx.unique_name("sim2real-behav-sesv2-topic-")
    topic_arn = sns.create_topic(Name=topic_name)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    configuration_set_arn = f"arn:aws:ses:{ctx.region}:{account}:configuration-set/{cs_name}"
    topic_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ses.amazonaws.com"},
            "Action": "sns:Publish",
            "Resource": topic_arn,
            "Condition": {
                "StringEquals": {"AWS:SourceAccount": account},
                "ArnLike": {"AWS:SourceArn": configuration_set_arn},
            },
        }],
    })
    sns.set_topic_attributes(TopicArn=topic_arn, AttributeName="Policy", AttributeValue=topic_policy)

    dest_name = ctx.unique_name("sim2real-behav-sesv2-dest-")
    real_destination = {
        "Enabled": True,
        "MatchingEventTypes": ["BOUNCE", "COMPLAINT"],
        "SnsDestination": {"TopicArn": topic_arn},
    }
    ses.create_configuration_set_event_destination(
        ConfigurationSetName=cs_name, EventDestinationName=dest_name,
        EventDestination=real_destination,
    )
    ctx.on_cleanup(_teardown(
        lambda: ses.delete_configuration_set_event_destination(
            ConfigurationSetName=cs_name, EventDestinationName=dest_name,
        ), "NotFoundException",
    ))

    def _one_destination():
        got = ses.get_configuration_set_event_destinations(ConfigurationSetName=cs_name)
        dests = got["EventDestinations"]
        names = [d["Name"] for d in dests]
        assert names == [dest_name], f"expected only {dest_name!r}, got {names!r}"
        d = dests[0]
        assert d["Enabled"] is True, f"expected Enabled True, got {d['Enabled']!r}"
        assert set(d["MatchingEventTypes"]) == {"BOUNCE", "COMPLAINT"}, (
            f"expected {{'BOUNCE', 'COMPLAINT'}}, got {set(d['MatchingEventTypes'])!r}"
        )
        assert d["SnsDestination"]["TopicArn"] == topic_arn, (
            f"expected TopicArn {topic_arn!r}, got {d['SnsDestination']['TopicArn']!r}"
        )
        assert "CloudWatchDestination" not in d, (
            f"a CloudWatchDestination appeared on the real destination: {d!r}"
        )
        return d

    _one_destination()

    _ALREADY_EXISTS = (
        "AlreadyExistsException",
        f"An event destination with name <{dest_name}> already exists for configuration "
        f"set <{cs_name}>.",
    )
    conflicting_definition = {
        "Enabled": False,
        "MatchingEventTypes": ["SEND"],
        "CloudWatchDestination": {
            "DimensionConfigurations": [{
                "DimensionName": "sim2realdim",
                "DimensionValueSource": "MESSAGE_TAG",
                "DefaultDimensionValue": "none",
            }],
        },
    }
    expect_error(
        lambda: ses.create_configuration_set_event_destination(
            ConfigurationSetName=cs_name, EventDestinationName=dest_name,
            EventDestination=conflicting_definition,
        ),
        *_ALREADY_EXISTS,
    )
    _one_destination()

    second_dest_name = ctx.unique_name("sim2real-behav-sesv2-dest-second-")
    ses.create_configuration_set_event_destination(
        ConfigurationSetName=cs_name, EventDestinationName=second_dest_name,
        EventDestination={
            "Enabled": True,
            "MatchingEventTypes": ["SEND"],
            "SnsDestination": {"TopicArn": topic_arn},
        },
    )
    ctx.on_cleanup(_teardown(
        lambda: ses.delete_configuration_set_event_destination(
            ConfigurationSetName=cs_name, EventDestinationName=second_dest_name,
        ), "NotFoundException",
    ))
    got_both = ses.get_configuration_set_event_destinations(ConfigurationSetName=cs_name)
    names_both = {d["Name"] for d in got_both["EventDestinations"]}
    assert names_both == {dest_name, second_dest_name}, (
        f"expected {{{dest_name!r}, {second_dest_name!r}}}, got {names_both!r}"
    )

    ses.delete_configuration_set_event_destination(
        ConfigurationSetName=cs_name, EventDestinationName=second_dest_name,
    )
    _one_destination()

    unknown_dest_name = ctx.unique_name("sim2real-behav-sesv2-dest-unknown-")
    _NOT_FOUND = (
        "NotFoundException",
        f"An event destination with name <{unknown_dest_name}> does not exist for "
        f"configuration set <{cs_name}>.",
    )
    update_for_unknown = {
        "Enabled": False,
        "MatchingEventTypes": ["SEND"],
        "SnsDestination": {"TopicArn": topic_arn},
    }
    expect_error(
        lambda: ses.update_configuration_set_event_destination(
            ConfigurationSetName=cs_name, EventDestinationName=unknown_dest_name,
            EventDestination=update_for_unknown,
        ),
        *_NOT_FOUND,
    )
    _one_destination()

    ses.update_configuration_set_event_destination(
        ConfigurationSetName=cs_name, EventDestinationName=dest_name,
        EventDestination=update_for_unknown,
    )
    updated = ses.get_configuration_set_event_destinations(ConfigurationSetName=cs_name)
    updated_dest = updated["EventDestinations"][0]
    assert updated_dest["Name"] == dest_name, f"unexpected name {updated_dest['Name']!r}"
    assert updated_dest["Enabled"] is False, f"expected Enabled False, got {updated_dest['Enabled']!r}"
    assert set(updated_dest["MatchingEventTypes"]) == {"SEND"}, (
        f"expected {{'SEND'}}, got {set(updated_dest['MatchingEventTypes'])!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
