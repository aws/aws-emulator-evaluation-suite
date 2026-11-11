"""create-event-destination-on-nonexistent-configset-denied."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-event-destination-on-nonexistent-configset-denied"
GROUP = "overly-permissive"
SERVICES = ["pinpoint-sms-voice"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConfigurationSetEventDestination on a never-created configuration set is refused with HTTP
    403 AccessDeniedException "Access Denied", and ListConfigurationSets does not show the set."""
    client = ctx.client("pinpoint-sms-voice")
    cfg_name = ctx.unique_name("sim2real-behav-cfgset-")
    fake_topic_arn = f"arn:aws:sns:{ctx.region}:123456789012:{ctx.unique_name('fake-topic-')}"

    try:
        client.create_configuration_set_event_destination(
            ConfigurationSetName=cfg_name,
            EventDestinationName="sim2real-dest",
            EventDestination={
                "Enabled": True,
                "MatchingEventTypes": ["ANSWERED"],
                "SnsDestination": {"TopicArn": fake_topic_arn},
            },
        )
        raise AssertionError("CreateConfigurationSetEventDestination unexpectedly succeeded")
    except ClientError as e:
        err = e.response["Error"]
        code = err["Code"]
        assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
        # representation depth: the error envelope itself is well-formed, not just the
        # code -- a non-empty human-readable Message and the 403-class HTTP status
        # botocore surfaces via ResponseMetadata.
        assert err.get("Message") == "Access Denied", (
            f"expected the AccessDeniedException Message 'Access Denied', got {err.get('Message')!r}"
        )
        status = e.response["ResponseMetadata"]["HTTPStatusCode"]
        assert status == 403, f"expected HTTP 403 for AccessDeniedException, got {status}"

    # effect absent: the configuration set the destination would have hung off of
    # never surfaces in ListConfigurationSets -- an independent read at a different
    # operation than the one that was denied.
    names: list[str] = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        page = client.list_configuration_sets(**kwargs)
        names.extend(page.get("ConfigurationSets", []))
        token = page.get("NextToken")
        if not token:
            break
    assert cfg_name not in names, f"{cfg_name} must not appear after a denied create"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
