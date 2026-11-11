"""create-event-destination-denied-across-destination-types."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-event-destination-denied-across-destination-types"
GROUP = "overly-permissive"
SERVICES = ["pinpoint-sms-voice"]


def _error_code(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConfigurationSetEventDestination is refused with AccessDeniedException and the exact
    message for SNS, CloudWatch Logs and Kinesis Firehose targets alike, and ListConfigurationSets shows
    no set of that name before or after."""
    client = ctx.client("pinpoint-sms-voice")
    cfg_name = ctx.unique_name("sim2real-behav-cfgset-")
    fake_topic_arn = f"arn:aws:sns:{ctx.region}:123456789012:{ctx.unique_name('fake-topic-')}"
    fake_log_group_arn = f"arn:aws:logs:{ctx.region}:123456789012:log-group:{ctx.unique_name('fake-lg-')}:*"
    fake_role_arn = f"arn:aws:iam::123456789012:role/{ctx.unique_name('fake-role-')}"
    fake_stream_arn = f"arn:aws:firehose:{ctx.region}:123456789012:deliverystream/{ctx.unique_name('fake-stream-')}"

    before = client.list_configuration_sets()
    assert "ConfigurationSets" in before, (
        "ListConfigurationSets did not return a well-formed page -- cannot conclude the "
        "write path (not credentials) is what is denied"
    )
    assert cfg_name not in before["ConfigurationSets"], f"{cfg_name} unexpectedly already exists"

    attempts = {
        "sns": {"Enabled": True, "MatchingEventTypes": ["ANSWERED"], "SnsDestination": {"TopicArn": fake_topic_arn}},
        "logs": {
            "Enabled": True,
            "MatchingEventTypes": ["FAILED"],
            "CloudWatchLogsDestination": {"LogGroupArn": fake_log_group_arn, "IamRoleArn": fake_role_arn},
        },
        "firehose": {
            "Enabled": True,
            "MatchingEventTypes": ["BUSY"],
            "KinesisFirehoseDestination": {"DeliveryStreamArn": fake_stream_arn, "IamRoleArn": fake_role_arn},
        },
    }

    # A destination that passes a role in another account is refused for that role.
    expected_messages = {
        "sns": "Access Denied",
        "logs": "Cross-account pass role is not allowed.",
        "firehose": "Cross-account pass role is not allowed.",
    }
    for kind, destination in attempts.items():
        code, message = _error_code(
            lambda destination=destination: client.create_configuration_set_event_destination(
                ConfigurationSetName=cfg_name,
                EventDestinationName=f"sim2real-{kind}-dest",
                EventDestination=destination,
            )
        )
        assert code == "AccessDeniedException", f"{kind} destination: expected AccessDeniedException, got {code!r}"
        assert message == expected_messages[kind], (
            f"{kind} destination: expected message {expected_messages[kind]!r}, got {message!r}"
        )

    after = client.list_configuration_sets()
    assert cfg_name not in after.get("ConfigurationSets", []), (
        f"{cfg_name} appeared in ListConfigurationSets after every "
        "CreateConfigurationSetEventDestination attempt was denied -- something got created"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
