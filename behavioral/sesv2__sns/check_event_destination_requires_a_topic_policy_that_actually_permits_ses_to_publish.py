"""event-destination-requires-a-topic-policy-that-actually-permits-ses-to-publish."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-destination-requires-a-topic-policy-that-actually-permits-ses-to-publish"
GROUP = "configuration-set-v2"
SERVICES = ["sesv2", "sns"]

_SID = "sim2realSesPublish"
_DESTINATION_NAME = "sim2real-ed-policy-probe"
# Bounds the read-back of each topic policy at SNS before SES evaluates it.
_POLICY_DEADLINE_S = 60.0
_POLICY_INTERVAL_S = 2.0


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SES refuses an SNS event destination whose topic policy denies it sns:Publish, with a
    specific error and no destination left behind; the identical call succeeds once the deny
    becomes an allow.

    Reference: https://docs.aws.amazon.com/ses/latest/dg/configure-sns-notifications.html
    """
    sesv2 = ctx.client("sesv2")
    sns = ctx.client("sns")
    account = ctx.client("sts").get_caller_identity()["Account"]

    config_set = _create_configuration_set(ctx)
    allow_topic = _create_topic(ctx, "allow-")
    deny_topic = _create_topic(ctx, "deny-")

    # Positive control: an allowing topic policy is accepted.
    _put_policy(ctx, allow_topic, _statement("Allow", allow_topic, account))
    sesv2.create_configuration_set_event_destination(
        ConfigurationSetName=config_set,
        EventDestinationName=_DESTINATION_NAME,
        EventDestination={
            "Enabled": True,
            "MatchingEventTypes": ["SEND", "BOUNCE"],
            "SnsDestination": {"TopicArn": allow_topic},
        },
    )
    destinations = _destinations(sesv2, config_set)
    assert _DESTINATION_NAME in destinations, (
        f"positive control: the event destination {_DESTINATION_NAME!r} was created against a topic "
        f"whose policy allows ses.amazonaws.com:Publish but GetConfigurationSetEventDestinations "
        f"does not list it: {sorted(destinations)}"
    )
    assert destinations[_DESTINATION_NAME]["SnsDestination"]["TopicArn"] == allow_topic, (
        f"positive control: SES reports TopicArn "
        f"{destinations[_DESTINATION_NAME]['SnsDestination']['TopicArn']!r}, expected {allow_topic!r}"
    )

    # Reset to a single destination slot so the negative and the restore use the identical name.
    sesv2.delete_configuration_set_event_destination(
        ConfigurationSetName=config_set, EventDestinationName=_DESTINATION_NAME
    )
    assert _DESTINATION_NAME not in _destinations(sesv2, config_set), (
        f"{_DESTINATION_NAME!r} survived DeleteConfigurationSetEventDestination, so the negative and "
        f"restore legs would not be using the identical call"
    )

    # The only change: the topic policy denies the SES service principal.
    _put_policy(ctx, deny_topic, _statement("Deny", deny_topic, account))

    code, message = _error(
        lambda: sesv2.create_configuration_set_event_destination(
            ConfigurationSetName=config_set,
            EventDestinationName=_DESTINATION_NAME,
            EventDestination={
                "Enabled": True,
                "MatchingEventTypes": ["SEND", "BOUNCE"],
                "SnsDestination": {"TopicArn": deny_topic},
            },
        )
    )
    assert code == "BadRequestException", (
        f"CreateConfigurationSetEventDestination against topic {deny_topic}, whose policy explicitly "
        f"denies ses.amazonaws.com:Publish, returned {code!r} ({message!r}); expected "
        f"BadRequestException. The identical call against the allow-policy topic succeeded."
    )
    expected_message = (
        f"Access denied to SNS topic <{deny_topic}>. Verify the SNS topic policy grants Amazon SES "
        f"the sns:Publish permission."
    )
    assert message == expected_message, (
        f"CreateConfigurationSetEventDestination against the deny-policy topic returned message "
        f"{message!r}; expected {expected_message!r}"
    )

    after_refusal = _destinations(sesv2, config_set)
    assert _DESTINATION_NAME not in after_refusal, (
        f"the refused CreateConfigurationSetEventDestination still created "
        f"{_DESTINATION_NAME!r}: {sorted(after_refusal)}"
    )

    _put_policy(ctx, deny_topic, _statement("Allow", deny_topic, account))
    sesv2.create_configuration_set_event_destination(
        ConfigurationSetName=config_set,
        EventDestinationName=_DESTINATION_NAME,
        EventDestination={
            "Enabled": True,
            "MatchingEventTypes": ["SEND", "BOUNCE"],
            "SnsDestination": {"TopicArn": deny_topic},
        },
    )
    restored = _destinations(sesv2, config_set)
    assert _DESTINATION_NAME in restored, (
        f"after the topic policy was changed from Deny to Allow, the identical "
        f"CreateConfigurationSetEventDestination did not produce {_DESTINATION_NAME!r}: "
        f"{sorted(restored)}"
    )
    assert restored[_DESTINATION_NAME]["SnsDestination"]["TopicArn"] == deny_topic, (
        f"SES reports TopicArn {restored[_DESTINATION_NAME]['SnsDestination']['TopicArn']!r} for the "
        f"restored destination, expected the once-denied topic {deny_topic!r}"
    )
    final_policy = json.loads(
        sns.get_topic_attributes(TopicArn=deny_topic)["Attributes"]["Policy"]
    )
    effects = {
        statement["Effect"]
        for statement in final_policy["Statement"]
        if statement.get("Sid") == _SID
    }
    assert effects == {"Allow"}, (
        f"the restored policy on {deny_topic} carries Sid {_SID!r} with effects {sorted(effects)}, "
        f"expected exactly {{'Allow'}}"
    )


def _create_configuration_set(ctx) -> str:
    sesv2 = ctx.client("sesv2")
    name = ctx.unique_name("sim2real-behav-edpolicy-")
    sesv2.create_configuration_set(
        ConfigurationSetName=name,
        Tags=[
            {"Key": "sim2real-managed", "Value": "true"},
            {"Key": "sim2real-check", "Value": CHECK},
        ],
    )
    ctx.on_cleanup(lambda: sesv2.delete_configuration_set(ConfigurationSetName=name))
    return name


def _create_topic(ctx, prefix: str) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-" + prefix),
        Tags=[
            {"Key": "sim2real-managed", "Value": "true"},
            {"Key": "sim2real-check", "Value": CHECK},
        ],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _statement(effect: str, topic_arn: str, account: str) -> dict:
    """The single policy statement; the legs differ only in Effect."""
    return {
        "Sid": _SID,
        "Effect": effect,
        "Principal": {"Service": "ses.amazonaws.com"},
        "Action": "SNS:Publish",
        "Resource": topic_arn,
        "Condition": {"StringEquals": {"AWS:SourceAccount": account}},
    }


def _put_policy(ctx, topic_arn: str, statement: dict) -> None:
    """Install the policy and wait until SNS reports it, so an SES refusal is never caused by a
    policy that has not propagated yet. Raises on timeout."""
    sns = ctx.client("sns")
    policy = {"Version": "2012-10-17", "Statement": [statement]}
    sns.set_topic_attributes(
        TopicArn=topic_arn, AttributeName="Policy", AttributeValue=json.dumps(policy)
    )
    wanted = statement["Effect"]
    deadline = time.monotonic() + _POLICY_DEADLINE_S
    observed = None
    while time.monotonic() < deadline:
        attributes = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
        raw = attributes.get("Policy")
        if raw:
            observed = [
                entry
                for entry in json.loads(raw)["Statement"]
                if entry.get("Sid") == _SID and entry.get("Effect") == wanted
            ]
            if observed:
                return
        time.sleep(_POLICY_INTERVAL_S)
    raise AssertionError(
        f"SNS never reported a {wanted!r} statement with Sid {_SID!r} on {topic_arn} within "
        f"{_POLICY_DEADLINE_S}s (last matching statements={observed!r}); SES cannot be asked to "
        f"evaluate a policy that has not landed"
    )


def _destinations(sesv2, config_set: str) -> dict:
    response = sesv2.get_configuration_set_event_destinations(ConfigurationSetName=config_set)
    return {entry["Name"]: entry for entry in response.get("EventDestinations", [])}


def _error(fn) -> tuple[str, str]:
    """The error code and message; raises if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(
        "CreateConfigurationSetEventDestination succeeded against an SNS topic whose policy "
        "explicitly denies ses.amazonaws.com:Publish; SES must refuse a destination it cannot "
        "publish to"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
