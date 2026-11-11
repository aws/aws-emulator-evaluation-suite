"""get-configuration-set-event-destinations-empty-name-validation."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-configuration-set-event-destinations-empty-name-validation"
GROUP = "error-semantics"
SERVICES = ["pinpoint-sms-voice"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetConfigurationSetEventDestinations with an empty ConfigurationSetName gets BadRequestException
    with the exact missing-parameter message, while a well-formed nonexistent name gets
    AccessDeniedException "Access Denied"."""
    client = ctx.client("pinpoint-sms-voice")
    missing_name = ctx.unique_name("sim2real-behav-missing-cfgset-")

    # positive control: a well-formed name the caller cannot read gets denied at
    # authorization, not treated as a malformed request.
    try:
        client.get_configuration_set_event_destinations(ConfigurationSetName=missing_name)
        raise AssertionError(f"expected AccessDeniedException for a well-formed but nonexistent set {missing_name!r}")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "AccessDeniedException", (
            f"expected AccessDeniedException for a well-formed nonexistent set, got {code!r}"
        )
        denied_message = e.response["Error"].get("Message")
        assert denied_message == "Access Denied", f"expected the message 'Access Denied', got {denied_message!r}"

    try:
        client.get_configuration_set_event_destinations(ConfigurationSetName="")
        raise AssertionError("GetConfigurationSetEventDestinations unexpectedly accepted an empty ConfigurationSetName")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message", "")
        assert code == "BadRequestException", (
            f"expected BadRequestException (missing-parameter, caught before authorization), got {code!r}"
        )
        expected = "Missing required request parameters: [ConfigurationSetName]"
        assert message == expected, f"expected the missing-parameter message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
