"""get-configuration-set-event-destinations-nonexistent-configset-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-configuration-set-event-destinations-nonexistent-configset-error"
GROUP = "error-semantics"
SERVICES = ["pinpoint-sms-voice"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetConfigurationSetEventDestinations on a never-created configuration set is refused with HTTP
    403 AccessDeniedException "Access Denied", while ListConfigurationSets succeeds."""
    client = ctx.client("pinpoint-sms-voice")
    missing_name = ctx.unique_name("sim2real-behav-missing-cfgset-")

    # positive control: the account and credentials are otherwise healthy for this
    # service -- only the resource-scoped action is gated, not every call.
    healthy = client.list_configuration_sets()
    assert "ConfigurationSets" in healthy, "ListConfigurationSets must succeed as a positive control"

    try:
        client.get_configuration_set_event_destinations(ConfigurationSetName=missing_name)
        raise AssertionError("GetConfigurationSetEventDestinations unexpectedly succeeded on a missing set")
    except ClientError as e:
        err = e.response["Error"]
        code = err["Code"]
        assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
        assert err.get("Message") == 'Access Denied', (
            f"expected the AccessDeniedException Message 'Access Denied', got {err.get('Message')!r}"
        )
        status = e.response["ResponseMetadata"]["HTTPStatusCode"]
        assert status == 403, f"expected HTTP 403 for AccessDeniedException, got {status}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
