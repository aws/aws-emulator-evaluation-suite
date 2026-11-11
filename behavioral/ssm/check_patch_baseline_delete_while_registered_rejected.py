"""patch-baseline-delete-while-registered-rejected."""
from __future__ import annotations

from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "patch-baseline-delete-while-registered-rejected"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePatchBaseline is rejected while the baseline is still registered to a patch group;
    the baseline and its registration remain fully intact, and deleting succeeds once
    deregistered (positive control)."""
    ssm = ctx.client("ssm")
    baseline_id = ssm.create_patch_baseline(
        Name=ctx.unique_name("sim2real-ssm-inuse-baseline-"),
        OperatingSystem="AMAZON_LINUX_2",
        ApprovalRules={
            "PatchRules": [
                {
                    "PatchFilterGroup": {
                        "PatchFilters": [
                            {"Key": "CLASSIFICATION", "Values": ["Security"]},
                        ]
                    },
                    "ApproveAfterDays": 7,
                }
            ]
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["BaselineId"]
    ctx.on_cleanup(lambda: _safe(lambda: ssm.delete_patch_baseline(BaselineId=baseline_id)))

    patch_group = ctx.unique_name("sim2real-inuse-patch-group-")
    ssm.register_patch_baseline_for_patch_group(BaselineId=baseline_id, PatchGroup=patch_group)
    ctx.on_cleanup(
        lambda: _safe(
            lambda: ssm.deregister_patch_baseline_for_patch_group(
                BaselineId=baseline_id, PatchGroup=patch_group
            )
        )
    )

    code, message = _error(lambda: ssm.delete_patch_baseline(BaselineId=baseline_id))
    assert code == "ResourceInUseException", code
    assert message == f"PatchBaseline to be deleted is used for Patch Group: {patch_group}", message

    # Effect absent: the baseline is still fully present and still registered.
    still_there = ssm.get_patch_baseline(BaselineId=baseline_id)
    assert still_there["BaselineId"] == baseline_id, (
        f"expected baseline {baseline_id} to survive the rejected delete, got {still_there!r}"
    )
    mapping = _find_patch_group_mapping(ssm, patch_group)
    assert mapping is not None and mapping["BaselineIdentity"]["BaselineId"] == baseline_id, (
        f"expected patch group {patch_group} still mapped to {baseline_id}, got {mapping!r}"
    )

    # Positive control: deregistering first makes the delete succeed.
    ssm.deregister_patch_baseline_for_patch_group(BaselineId=baseline_id, PatchGroup=patch_group)
    ssm.delete_patch_baseline(BaselineId=baseline_id)
    after_code, after_message = _error(lambda: ssm.get_patch_baseline(BaselineId=baseline_id))
    assert after_code == "DoesNotExistException", after_code
    assert after_message == "Patch Baseline to be retrieved does not exist.", after_message


def _find_patch_group_mapping(ssm, patch_group: str):
    paginator = ssm.get_paginator("describe_patch_groups")
    for page in paginator.paginate():
        for mapping in page.get("Mappings", []):
            if mapping["PatchGroup"] == patch_group:
                return mapping
    return None


def _error(fn):
    """Return the (code, message) of the ClientError fn raises; raise if fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"the call was expected to be refused but it succeeded: {result!r}")


def _safe(fn: Callable[[], Any]) -> None:
    fn()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
