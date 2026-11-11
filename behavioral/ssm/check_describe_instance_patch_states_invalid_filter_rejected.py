"""describe-instance-patch-states-invalid-filter-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-instance-patch-states-invalid-filter-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeInstancePatchStatesForPatchGroup returns empty results unfiltered and with a
    documented filter Key, but fails with ValidationException "Unknown Filter Key:
    NotARealFilterKey" for an unsupported Key."""
    ssm = ctx.client("ssm")
    patch_group = ctx.unique_name("sim2real-behav-patchgrp-")

    # Positive control: no instances registered to the group yet, but the call
    # itself (unfiltered) is well-formed and must not error.
    control = ssm.describe_instance_patch_states_for_patch_group(PatchGroup=patch_group)
    assert control.get("InstancePatchStates", []) == [], (
        f"expected no patch states for a never-registered patch group, "
        f"got {control.get('InstancePatchStates')!r}"
    )

    # Second positive control: a documented, well-formed filter Key is accepted (and,
    # against a never-registered group, still resolves to an empty page) -- this is
    # what tells apart "rejects this specific unsupported Key" from "rejects any
    # request carrying a Filters member at all".
    good_filter = ssm.describe_instance_patch_states_for_patch_group(
        PatchGroup=patch_group,
        Filters=[{"Key": "InstalledCount", "Type": "Equal", "Values": ["0"]}],
    )
    assert good_filter.get("InstancePatchStates", []) == [], (
        f"expected a well-formed filter on a documented Key to be accepted and "
        f"resolve to an empty page, got {good_filter.get('InstancePatchStates')!r}"
    )

    # Negative: an unsupported filter Key.
    code, message = _error(
        lambda: ssm.describe_instance_patch_states_for_patch_group(
            PatchGroup=patch_group,
            Filters=[{"Key": "NotARealFilterKey", "Type": "Equal", "Values": ["1"]}],
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "Unknown Filter Key: NotARealFilterKey", message

    # Control still works after the rejected call.
    still_ok = ssm.describe_instance_patch_states_for_patch_group(PatchGroup=patch_group)
    assert still_ok.get("InstancePatchStates", []) == [], (
        f"expected no patch states for the never-registered patch group after the "
        f"rejected call, got {still_ok.get('InstancePatchStates')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
