"""event-destination-unowned-sns-topic-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-destination-unowned-sns-topic-fails"
GROUP = 'overly-permissive'
SERVICES = ['ses']

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _account_id(ctx):
    if not hasattr(ctx, "_ses_account_id"):
        ctx._ses_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._ses_account_id


def _dest_map(ses, cfg_name):
    desc = ses.describe_configuration_set(
        ConfigurationSetName=cfg_name, ConfigurationSetAttributeNames=["eventDestinations"]
    )
    return {d["Name"]: d for d in desc.get("EventDestinations", [])}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConfigurationSetEventDestination rejects an SNS destination for a missing topic
    (InvalidSNSDestination), leaves it unattached, and accepts it once the topic exists."""
    ses = ctx.client("ses")
    sns = ctx.client("sns")
    cfg_name = ctx.unique_name("sim2real-behav-cfgset-sns-")
    ses.create_configuration_set(ConfigurationSet={"Name": cfg_name})
    ctx.on_cleanup(lambda _n=cfg_name: ses.delete_configuration_set(ConfigurationSetName=_n))

    # --- Positive control: an owned topic attaches fine, so SNS event destinations are not
    #     broken wholesale in this account.
    live_topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-live-topic-"))["TopicArn"]
    ctx.on_cleanup(lambda _a=live_topic_arn: sns.delete_topic(TopicArn=_a))
    live_dest_name = ctx.unique_name("sim2real-behav-dest-live-")
    ses.create_configuration_set_event_destination(
        ConfigurationSetName=cfg_name,
        EventDestination={
            "Name": live_dest_name,
            "Enabled": True,
            "MatchingEventTypes": ["send"],
            "SNSDestination": {"TopicARN": live_topic_arn},
        },
    )
    names = _dest_map(ses, cfg_name)
    assert live_dest_name in names, (
        f"positive control: destination on an owned topic did not attach, got {list(names)}"
    )

    # --- Break exactly one thing: a well-formed ARN in the caller's own account/region, but no
    #     such topic exists.
    ghost_topic_name = ctx.unique_name("sim2real-behav-ghost-topic-")
    ghost_topic_arn = f"arn:aws:sns:{ctx.region}:{_account_id(ctx)}:{ghost_topic_name}"
    dest_name = ctx.unique_name("sim2real-behav-dest-")
    destination = {
        "Name": dest_name,
        "Enabled": True,
        "MatchingEventTypes": ["send"],
        "SNSDestination": {"TopicARN": ghost_topic_arn},
    }
    err, msg = _err(
        lambda: ses.create_configuration_set_event_destination(
            ConfigurationSetName=cfg_name, EventDestination=destination
        )
    )
    assert err == "InvalidSNSDestination", (
        f"expected InvalidSNSDestination for a non-existent topic, got {err!r}: {msg!r}"
    )
    expected_msg = f"SNS topic <{ghost_topic_arn}> not found."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # The rejected destination must not have been attached.
    names = _dest_map(ses, cfg_name)
    assert dest_name not in names, f"rejected event destination was still attached: {list(names)}"

    # --- Restore: create the exact topic the ARN pointed at, then retry the identical call.
    sns.create_topic(Name=ghost_topic_name)
    ctx.on_cleanup(lambda _a=ghost_topic_arn: sns.delete_topic(TopicArn=_a))
    ses.create_configuration_set_event_destination(
        ConfigurationSetName=cfg_name, EventDestination=destination
    )
    names = _dest_map(ses, cfg_name)
    restored = names.get(dest_name, {}).get("SNSDestination", {}).get("TopicARN")
    assert restored == ghost_topic_arn, (
        f"restore: identical call did not succeed once the topic existed, got {names.get(dest_name)!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
