"""patch-baseline-register-conflicting-os-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "patch-baseline-register-conflicting-os-rejected"
GROUP = "server-side"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second same-OS baseline on a patch group fails AlreadyExistsException, mapping unchanged.

    Deregistering the first lets the same call succeed; a different-OS baseline registers."""
    ssm = ctx.client("ssm")
    patch_group = ctx.unique_name("sim2real-pg-")
    # CreatePatchBaseline requires ApprovalRules or ApprovedPatches.
    approval_rules = {
        "PatchRules": [
            {
                "PatchFilterGroup": {"PatchFilters": [{"Key": "PRODUCT", "Values": ["*"]}]},
                "ApproveAfterDays": 7,
            }
        ]
    }

    name_1 = ctx.unique_name("sim2real-bl1-")
    baseline_1 = ssm.create_patch_baseline(
        Name=name_1,
        OperatingSystem="AMAZON_LINUX_2",
        ApprovalRules=approval_rules,
        Tags=[{"Key": "sim2real-behav-probe", "Value": name_1}],
    )["BaselineId"]
    ctx.on_cleanup(lambda: ssm.delete_patch_baseline(BaselineId=baseline_1))
    name_2 = ctx.unique_name("sim2real-bl2-")
    baseline_2 = ssm.create_patch_baseline(
        Name=name_2,
        OperatingSystem="AMAZON_LINUX_2",
        ApprovalRules=approval_rules,
        Tags=[{"Key": "sim2real-behav-probe", "Value": name_2}],
    )["BaselineId"]
    ctx.on_cleanup(lambda: ssm.delete_patch_baseline(BaselineId=baseline_2))
    name_u = ctx.unique_name("sim2real-blu-")
    baseline_ubuntu = ssm.create_patch_baseline(
        Name=name_u,
        OperatingSystem="UBUNTU",
        ApprovalRules=approval_rules,
        Tags=[{"Key": "sim2real-behav-probe", "Value": name_u}],
    )["BaselineId"]
    ctx.on_cleanup(lambda: ssm.delete_patch_baseline(BaselineId=baseline_ubuntu))


    ssm.register_patch_baseline_for_patch_group(BaselineId=baseline_1, PatchGroup=patch_group)
    ctx.on_cleanup(
        lambda: ssm.deregister_patch_baseline_for_patch_group(
            BaselineId=baseline_1, PatchGroup=patch_group
        )
    )

    code, message = _error(
        lambda: ssm.register_patch_baseline_for_patch_group(
            BaselineId=baseline_2, PatchGroup=patch_group
        )
    )
    assert code == "AlreadyExistsException", code
    assert message == (
        f"Patch Group {patch_group} already has a baseline registered for OperatingSystem "
        f"AMAZON_LINUX_2."
    ), message

    mapping = ssm.get_patch_baseline_for_patch_group(
        PatchGroup=patch_group, OperatingSystem="AMAZON_LINUX_2"
    )
    assert mapping["BaselineId"] == baseline_1, mapping

    ssm.deregister_patch_baseline_for_patch_group(BaselineId=baseline_1, PatchGroup=patch_group)
    ssm.register_patch_baseline_for_patch_group(BaselineId=baseline_2, PatchGroup=patch_group)
    ctx.on_cleanup(
        lambda: ssm.deregister_patch_baseline_for_patch_group(
            BaselineId=baseline_2, PatchGroup=patch_group
        )
    )
    restored_mapping = ssm.get_patch_baseline_for_patch_group(
        PatchGroup=patch_group, OperatingSystem="AMAZON_LINUX_2"
    )
    assert restored_mapping["BaselineId"] == baseline_2, restored_mapping

    ssm.register_patch_baseline_for_patch_group(BaselineId=baseline_ubuntu, PatchGroup=patch_group)
    ctx.on_cleanup(
        lambda: ssm.deregister_patch_baseline_for_patch_group(
            BaselineId=baseline_ubuntu, PatchGroup=patch_group
        )
    )
    ubuntu_mapping = ssm.get_patch_baseline_for_patch_group(
        PatchGroup=patch_group, OperatingSystem="UBUNTU"
    )
    assert ubuntu_mapping["BaselineId"] == baseline_ubuntu, ubuntu_mapping


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected AlreadyExistsException but the call SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
