"""register-patch-baseline-duplicate-patch-group-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-patch-baseline-duplicate-patch-group-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Registering a second same-OS baseline to a mapped patch group fails with AlreadyExistsException
    naming the group and OS and keeps the mapping, while the second baseline registers to another group
    and, after deregistration, to the first."""
    ssm = ctx.client("ssm")
    os_name = "AMAZON_LINUX_2"
    approval_rules = {
        "PatchRules": [
            {
                "PatchFilterGroup": {
                    "PatchFilters": [{"Key": "CLASSIFICATION", "Values": ["Security"]}]
                },
                "ApproveAfterDays": 7,
            }
        ]
    }

    baseline_a = ssm.create_patch_baseline(
        Name=ctx.unique_name("sim2real-baseline-a-"),
        OperatingSystem=os_name,
        ApprovalRules=approval_rules,
    )["BaselineId"]
    ctx.on_cleanup(lambda: _safe(lambda: ssm.delete_patch_baseline(BaselineId=baseline_a)))
    baseline_b = ssm.create_patch_baseline(
        Name=ctx.unique_name("sim2real-baseline-b-"),
        OperatingSystem=os_name,
        ApprovalRules=approval_rules,
    )["BaselineId"]
    ctx.on_cleanup(lambda: _safe(lambda: ssm.delete_patch_baseline(BaselineId=baseline_b)))


    patch_group_1 = ctx.unique_name("sim2real-pg1-")
    patch_group_2 = ctx.unique_name("sim2real-pg2-")

    ssm.register_patch_baseline_for_patch_group(BaselineId=baseline_a, PatchGroup=patch_group_1)
    ctx.on_cleanup(
        lambda: _safe(
            lambda: ssm.deregister_patch_baseline_for_patch_group(
                BaselineId=baseline_a, PatchGroup=patch_group_1
            )
        )
    )

    # Negative: baseline_b tries to claim the same patch group already mapped to baseline_a.
    code, message = _client_error(
        lambda: ssm.register_patch_baseline_for_patch_group(
            BaselineId=baseline_b, PatchGroup=patch_group_1
        )
    )
    assert code == "AlreadyExistsException", code
    assert message == (
        f"Patch Group {patch_group_1} already has a baseline registered for "
        f"OperatingSystem {os_name}."
    ), message

    # Effect absent: patch_group_1 is still mapped to baseline_a, not baseline_b.
    mapping = ssm.get_patch_baseline_for_patch_group(
        PatchGroup=patch_group_1, OperatingSystem=os_name
    )
    assert mapping["BaselineId"] == baseline_a, mapping["BaselineId"]

    # Restore: once patch_group_1 is freed from baseline_a, the identical call that was just
    # rejected (baseline_b, same patch_group_1) succeeds — the block is the state, not the input.
    ssm.deregister_patch_baseline_for_patch_group(BaselineId=baseline_a, PatchGroup=patch_group_1)
    ssm.register_patch_baseline_for_patch_group(BaselineId=baseline_b, PatchGroup=patch_group_1)
    ctx.on_cleanup(
        lambda: _safe(
            lambda: ssm.deregister_patch_baseline_for_patch_group(
                BaselineId=baseline_b, PatchGroup=patch_group_1
            )
        )
    )
    restored_mapping = ssm.get_patch_baseline_for_patch_group(
        PatchGroup=patch_group_1, OperatingSystem=os_name
    )
    assert restored_mapping["BaselineId"] == baseline_b, (
        f"expected patch_group_1 restored to baseline_b, got {restored_mapping['BaselineId']}"
    )

    # Positive control: baseline_b registers cleanly against a distinct, unclaimed patch group.
    ssm.register_patch_baseline_for_patch_group(BaselineId=baseline_b, PatchGroup=patch_group_2)
    ctx.on_cleanup(
        lambda: _safe(
            lambda: ssm.deregister_patch_baseline_for_patch_group(
                BaselineId=baseline_b, PatchGroup=patch_group_2
            )
        )
    )
    mapping_2 = ssm.get_patch_baseline_for_patch_group(
        PatchGroup=patch_group_2, OperatingSystem=os_name
    )
    assert mapping_2["BaselineId"] == baseline_b, mapping_2["BaselineId"]


def _safe(fn) -> None:
    fn()


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
