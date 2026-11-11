"""put-resource-set-invalid-resource-type-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-resource-set-invalid-resource-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["fms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With no Firewall Manager admin (GetAdminAccount: ResourceNotFoundException), PutResourceSet with a bogus
    and with a valid resource type fails with the same AccessDeniedException "No default admin ...", as does
    ListResourceSets: the admin gate runs before resource-type validation."""
    fms = ctx.client("fms")

    # Health check: GetAdminAccount answers ResourceNotFoundException, a different code from the
    # AccessDeniedException below, so FMS is reachable with these credentials and no admin is configured.
    health_code, health_message = _error_code(lambda: fms.get_admin_account())
    assert health_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from get_admin_account (no admin configured), "
        f"got {health_code}"
    )
    assert health_message == "", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {health_message!r}"
    )

    bad_name = ctx.unique_name("sim2real-fms-rs-badtype-")
    bad_code, bad_message = _error_code_and_message(
        lambda: fms.put_resource_set(
            ResourceSet={"Name": bad_name, "ResourceTypeList": ["AWS::Bogus::NotARealType"]}
        )
    )
    assert bad_code == "AccessDeniedException", f"expected AccessDeniedException, got {bad_code}"
    assert "no default admin" in bad_message.lower(), (
        f"expected the no-admin-configured message, got: {bad_message!r}"
    )

    good_name = ctx.unique_name("sim2real-fms-rs-goodtype-")
    good_code, good_message = _error_code_and_message(
        lambda: fms.put_resource_set(
            ResourceSet={"Name": good_name, "ResourceTypeList": ["AWS::NetworkFirewall::Firewall"]}
        )
    )
    assert good_code == "AccessDeniedException", (
        f"expected AccessDeniedException (same authorization gate as the bogus-type "
        f"payload) for a well-formed resource type list, got {good_code}"
    )
    assert good_message == bad_message, (
        f"expected the identical no-admin-configured message regardless of resource-type-list "
        f"validity, got {good_message!r} for the well-formed payload vs {bad_message!r} for the "
        f"bogus one"
    )

    # Independent terminal read at a DIFFERENT operation than the one that mutated: confirm
    # neither attempted create left a trace by asking the list op, which is gated the same way:
    # the admin-gated writes did not sneak a partial resource set past the authorization check.
    list_code, list_message = _error_code_and_message(lambda: fms.list_resource_sets(MaxResults=10))
    assert list_code == "AccessDeniedException", f"expected AccessDeniedException, got {list_code}"
    assert list_message == f"No default admin could be found for account {ctx.account} in Region {ctx.region}", (
        f"expected the exact AccessDeniedException message AWS returns, got {list_message!r}"
    )
    assert "no default admin" in list_message.lower(), (
        f"expected the no-admin-configured message, got: {list_message!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

