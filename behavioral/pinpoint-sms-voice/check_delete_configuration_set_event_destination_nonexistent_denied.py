"""delete-configuration-set-event-destination-nonexistent-denied."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-configuration-set-event-destination-nonexistent-denied"
GROUP = "overly-permissive"
SERVICES = ["pinpoint-sms-voice"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteConfigurationSetEventDestination on a never-created configuration set and destination is
    refused with AccessDeniedException "Access Denied", while ListConfigurationSets succeeds."""
    client = ctx.client("pinpoint-sms-voice")
    cfg_name = ctx.unique_name("sim2real-behav-cfgset-")

    control = client.list_configuration_sets()
    assert "ConfigurationSets" in control, "positive control failed: ListConfigurationSets itself was rejected"

    try:
        client.delete_configuration_set_event_destination(
            ConfigurationSetName=cfg_name, EventDestinationName="sim2real-dest"
        )
        raise AssertionError("DeleteConfigurationSetEventDestination unexpectedly succeeded")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
        message = e.response["Error"].get("Message")
        assert message == "Access Denied", f"expected the message 'Access Denied', got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
