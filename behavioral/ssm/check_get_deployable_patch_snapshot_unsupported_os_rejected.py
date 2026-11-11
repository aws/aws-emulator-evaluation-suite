"""get-deployable-patch-snapshot-unsupported-os-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-deployable-patch-snapshot-unsupported-os-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDeployablePatchSnapshotForInstance from a caller outside the managed node is refused with
    AccessDeniedException naming the instance/credential mismatch; other SSM reads keep working.
    """
    ssm = ctx.client("ssm")

    # Positive control: an ordinary read-only SSM call still works.
    control = ssm.describe_available_patches(MaxResults=10)
    assert "Patches" in control, f"expected a Patches key, got keys={list(control)}"

    bogus_instance_id = "i-0123456789abcdef0"
    snapshot_id = str(uuid.uuid4())
    # The caller/instance identity check takes precedence over OS validation, so even an
    # instance that would trip UnsupportedOperatingSystem is refused as AccessDenied.
    error = _error(
        lambda: ssm.get_deployable_patch_snapshot_for_instance(
            InstanceId=bogus_instance_id, SnapshotId=snapshot_id
        )
    )
    assert error["Code"] == "AccessDeniedException", f"expected AccessDeniedException, got {error!r}"
    # The message separates "this caller cannot act as this instance" from "no permission at all".
    assert error["Message"] == (
        f"Instance Id {bogus_instance_id} doesn't match the credentials"
    ), error["Message"]

    still_ok = ssm.describe_available_patches(MaxResults=10)
    assert "Patches" in still_ok, f"expected a Patches key, got keys={list(still_ok)}"


def _error(fn):
    """Call fn(); return its botocore error dict, raising if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(
        f"real AWS rejects GetDeployablePatchSnapshotForInstance for a non-agent caller, "
        f"but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
