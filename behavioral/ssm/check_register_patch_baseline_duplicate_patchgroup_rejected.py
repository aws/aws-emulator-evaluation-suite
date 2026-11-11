"""register-patch-baseline-duplicate-patchgroup-rejected."""
from __future__ import annotations

from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-patch-baseline-duplicate-patchgroup-rejected"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Registering a patch group already mapped to another AMAZON_LINUX_2 baseline fails with
    AlreadyExistsException and the exact message and keeps the mapping; after deregistration the same call maps
    the group to the second baseline, as it does a distinct group."""
    ssm = ctx.client("ssm")
    baseline_a = ssm.create_patch_baseline(
        Name=ctx.unique_name("sim2real-ssm-dupreg-a-"),
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
    )["BaselineId"]
    ctx.on_cleanup(lambda: _safe(lambda: ssm.delete_patch_baseline(BaselineId=baseline_a)))
    baseline_b = ssm.create_patch_baseline(
        Name=ctx.unique_name("sim2real-ssm-dupreg-b-"),
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
    )["BaselineId"]
    ctx.on_cleanup(lambda: _safe(lambda: ssm.delete_patch_baseline(BaselineId=baseline_b)))

    patch_group = ctx.unique_name("sim2real-dupreg-group-")
    ssm.register_patch_baseline_for_patch_group(BaselineId=baseline_a, PatchGroup=patch_group)
    ctx.on_cleanup(
        lambda: _safe(
            lambda: ssm.deregister_patch_baseline_for_patch_group(
                BaselineId=baseline_a, PatchGroup=patch_group
            )
        )
    )

    code, message = _client_error(
        lambda: ssm.register_patch_baseline_for_patch_group(
            BaselineId=baseline_b, PatchGroup=patch_group
        )
    )
    assert code == "AlreadyExistsException", code
    assert message == (
        f"Patch Group {patch_group} already has a baseline registered for "
        "OperatingSystem AMAZON_LINUX_2."
    ), message

    mapping = _find_patch_group_mapping(ssm, patch_group)
    assert mapping is not None and mapping["BaselineIdentity"]["BaselineId"] == baseline_a, (
        "the rejected duplicate registration changed which baseline the patch group maps to"
    )

    # Restore: once the group is freed from baseline_a, the identical call that was just
    # rejected (baseline_b, same patch_group) succeeds — the block is the state, not the input.
    ssm.deregister_patch_baseline_for_patch_group(BaselineId=baseline_a, PatchGroup=patch_group)
    ssm.register_patch_baseline_for_patch_group(BaselineId=baseline_b, PatchGroup=patch_group)
    ctx.on_cleanup(
        lambda: _safe(
            lambda: ssm.deregister_patch_baseline_for_patch_group(
                BaselineId=baseline_b, PatchGroup=patch_group
            )
        )
    )
    restored_mapping = _find_patch_group_mapping(ssm, patch_group)
    assert (
        restored_mapping is not None
        and restored_mapping["BaselineIdentity"]["BaselineId"] == baseline_b
    ), f"expected patch group restored to baseline_b, got {restored_mapping}"

    # Positive control: a genuinely distinct patch group registers to baseline_b without issue.
    other_group = ctx.unique_name("sim2real-dupreg-group2-")
    ssm.register_patch_baseline_for_patch_group(BaselineId=baseline_b, PatchGroup=other_group)
    ctx.on_cleanup(
        lambda: _safe(
            lambda: ssm.deregister_patch_baseline_for_patch_group(
                BaselineId=baseline_b, PatchGroup=other_group
            )
        )
    )
    other_mapping = _find_patch_group_mapping(ssm, other_group)
    assert (
        other_mapping is not None
        and other_mapping["BaselineIdentity"]["BaselineId"] == baseline_b
    ), f"expected distinct patch group mapped to baseline_b, got {other_mapping}"


def _find_patch_group_mapping(ssm, patch_group: str):
    paginator = ssm.get_paginator("describe_patch_groups")
    for page in paginator.paginate():
        for mapping in page.get("Mappings", []):
            if mapping["PatchGroup"] == patch_group:
                return mapping
    return None


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _safe(fn: Callable[[], Any]) -> None:
    fn()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
