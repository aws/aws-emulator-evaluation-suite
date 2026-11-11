"""list-resources-in-protection-group-missing-group-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-resources-in-protection-group-missing-group-not-found"
GROUP = "error-semantics"
SERVICES = ["shield"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListResourcesInProtectionGroup for a never-created ProtectionGroupId raises ResourceNotFoundException
    with the group-specific message "The referenced protection-group does not exist.", not the account-level
    no-subscription message.
    """
    shield = ctx.client("shield")
    missing_id = ctx.unique_name("sim2real-nogrp-")
    err = _error(lambda: shield.list_resources_in_protection_group(ProtectionGroupId=missing_id))
    assert err["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err['Code']!r}"
    assert err.get("Message") == "The referenced protection-group does not exist.", (
        f"expected the group-specific not-found message (not the account-level 'subscription does "
        f"not exist' shape, which shares the same error code), got {err['Message']!r}"
    )


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError("expected list_resources_in_protection_group to raise, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
