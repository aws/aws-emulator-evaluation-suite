"""delete-configuration-set-nonexistent-denied."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-configuration-set-nonexistent-denied"
GROUP = "overly-permissive"
SERVICES = ["pinpoint-sms-voice"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteConfigurationSet on a never-created name is refused with HTTP 403 AccessDeniedException
    "Access Denied" (not NotFoundException), and ListConfigurationSets does not show the name."""
    client = ctx.client("pinpoint-sms-voice")
    missing_name = ctx.unique_name("sim2real-behav-missing-cfgset-")

    try:
        client.delete_configuration_set(ConfigurationSetName=missing_name)
        raise AssertionError("DeleteConfigurationSet on a never-created name unexpectedly succeeded")
    except ClientError as e:
        err = e.response["Error"]
        code = err["Code"]
        assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
        # representation depth: the error envelope itself is well-formed, not just the code -- a
        # non-empty human-readable Message and the 403-class HTTP status botocore surfaces via
        # ResponseMetadata.
        assert err.get("Message") == "Access Denied", (
            f"expected the AccessDeniedException Message 'Access Denied', got {err.get('Message')!r}"
        )
        status = e.response["ResponseMetadata"]["HTTPStatusCode"]
        assert status == 403, f"expected HTTP 403 for AccessDeniedException, got {status}"

    # effect absent: the name never surfaces in ListConfigurationSets either
    names: list[str] = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        page = client.list_configuration_sets(**kwargs)
        names.extend(page.get("ConfigurationSets", []))
        token = page.get("NextToken")
        if not token:
            break
    assert missing_name not in names, f"{missing_name} must not appear after a denied delete"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
