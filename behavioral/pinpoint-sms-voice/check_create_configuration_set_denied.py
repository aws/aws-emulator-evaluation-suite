"""create-configuration-set-denied."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-configuration-set-denied"
GROUP = "overly-permissive"
SERVICES = ["pinpoint-sms-voice"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConfigurationSet is refused with HTTP 403 AccessDeniedException "Access Denied" and
    ListConfigurationSets does not show the name afterwards."""
    client = ctx.client("pinpoint-sms-voice")
    name = ctx.unique_name("sim2real-behav-cfgset-")

    try:
        client.create_configuration_set(ConfigurationSetName=name)
        created = True
    except ClientError as e:
        created = False
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
    finally:
        if created:
            client.delete_configuration_set(ConfigurationSetName=name)
    assert not created, "CreateConfigurationSet unexpectedly succeeded"

    # effect absent: the name never surfaces in ListConfigurationSets
    names: list[str] = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        page = client.list_configuration_sets(**kwargs)
        names.extend(page.get("ConfigurationSets", []))
        token = page.get("NextToken")
        if not token:
            break
    assert name not in names, f"{name} must not appear after a denied create"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
