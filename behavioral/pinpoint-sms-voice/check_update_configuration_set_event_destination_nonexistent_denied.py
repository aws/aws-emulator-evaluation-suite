"""update-configuration-set-event-destination-nonexistent-denied."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-configuration-set-event-destination-nonexistent-denied"
GROUP = "overly-permissive"
SERVICES = ["pinpoint-sms-voice"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateConfigurationSetEventDestination on a never-created set is refused with
    AccessDeniedException (HTTP 403, 'Access Denied') while ListConfigurationSets succeeds, and
    the set still does not appear in ListConfigurationSets afterwards."""
    client = ctx.client("pinpoint-sms-voice")
    cfg_name = ctx.unique_name("sim2real-behav-cfgset-")
    fake_topic_arn = f"arn:aws:sns:{ctx.region}:123456789012:{ctx.unique_name('fake-topic-')}"

    # positive control: the read plane works, so a blanket credentials/region
    # failure cannot be what is producing the AccessDeniedException below.
    control = client.list_configuration_sets()
    assert "ConfigurationSets" in control, "ListConfigurationSets must be reachable in this account"

    try:
        client.update_configuration_set_event_destination(
            ConfigurationSetName=cfg_name,
            EventDestinationName="sim2real-dest",
            EventDestination={
                "Enabled": True,
                "MatchingEventTypes": ["ANSWERED"],
                "SnsDestination": {"TopicArn": fake_topic_arn},
            },
        )
        raise AssertionError("UpdateConfigurationSetEventDestination unexpectedly succeeded")
    except ClientError as e:
        err = e.response["Error"]
        code = err["Code"]
        assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
        assert err.get("Message") == 'Access Denied', (
            f"expected the AccessDeniedException Message 'Access Denied', got {err.get('Message')!r}"
        )
        status = e.response["ResponseMetadata"]["HTTPStatusCode"]
        assert status == 403, f"expected HTTP 403 for AccessDeniedException, got {status}"

    # effect absent: the denied Update must not have side-effected a configuration
    # set into existence under cfg_name.
    names: list[str] = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        page = client.list_configuration_sets(**kwargs)
        names.extend(page.get("ConfigurationSets", []))
        token = page.get("NextToken")
        if not token:
            break
    assert cfg_name not in names, f"{cfg_name} must not appear after a denied update"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
