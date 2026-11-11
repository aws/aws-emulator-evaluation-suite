"""update-configuration-set-event-destination-invalid-payload-still-denied."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-configuration-set-event-destination-invalid-payload-still-denied"
GROUP = "error-semantics"
SERVICES = ["pinpoint-sms-voice"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateConfigurationSetEventDestination with SNS and CloudWatch Logs destinations on a never-created
    set is refused 403 AccessDeniedException 'Cross-account pass role is not allowed.', and reading the
    set's destinations back is still refused with AccessDeniedException 'Access Denied'."""
    client = ctx.client("pinpoint-sms-voice")
    cfg_name = ctx.unique_name("sim2real-behav-cfgset-")
    fake_topic_arn = f"arn:aws:sns:{ctx.region}:123456789012:{ctx.unique_name('fake-topic-')}"
    fake_log_group_arn = f"arn:aws:logs:{ctx.region}:123456789012:log-group:{ctx.unique_name('fake-lg-')}:*"
    fake_role_arn = f"arn:aws:iam::123456789012:role/{ctx.unique_name('fake-role-')}"

    try:
        client.update_configuration_set_event_destination(
            ConfigurationSetName=cfg_name,
            EventDestinationName="sim2real-dest",
            EventDestination={
                "Enabled": True,
                "MatchingEventTypes": ["ANSWERED"],
                "SnsDestination": {"TopicArn": fake_topic_arn},
                "CloudWatchLogsDestination": {"LogGroupArn": fake_log_group_arn, "IamRoleArn": fake_role_arn},
            },
        )
        raise AssertionError("UpdateConfigurationSetEventDestination unexpectedly succeeded")
    except ClientError as e:
        err = e.response["Error"]
        code = err["Code"]
        assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
        # The destination passes a role in another account, which is refused for that role.
        assert err.get("Message") == 'Cross-account pass role is not allowed.', (
            f"expected the AccessDeniedException Message 'Cross-account pass role is not allowed.', got {err.get('Message')!r}"
        )
        status = e.response["ResponseMetadata"]["HTTPStatusCode"]
        assert status == 403, f"expected HTTP 403 for AccessDeniedException, got {status}"

    # effect absent, via an independent read operation: the denied update created
    # nothing, so the destination -- and the configuration set itself -- still
    # cannot be read back either.
    try:
        client.get_configuration_set_event_destinations(ConfigurationSetName=cfg_name)
        raise AssertionError("GetConfigurationSetEventDestinations unexpectedly succeeded on a set that was never created")
    except ClientError as e:
        read_code = e.response["Error"]["Code"]
        assert read_code == "AccessDeniedException", f"expected AccessDeniedException, got {read_code!r}"
        read_message = e.response["Error"].get("Message")
        assert read_message == "Access Denied", f"expected the message 'Access Denied', got {read_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
