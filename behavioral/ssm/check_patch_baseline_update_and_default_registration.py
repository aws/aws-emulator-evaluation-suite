"""patch-baseline-update-and-default-registration."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "patch-baseline-update-and-default-registration"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ssm-default-patch-baseline")
def run(ctx) -> None:
    """UpdatePatchBaseline mutates fields; RegisterDefaultPatchBaseline moves the OS default."""

    ssm = ctx.client("ssm")

    def _create_patch_baseline():
        name = ctx.unique_name("sim2real-behav-probe-baseline-")
        baseline_id = ssm.create_patch_baseline(
            Name=name,
            OperatingSystem="AMAZON_LINUX_2",
            ApprovalRules={
                "PatchRules": [
                    {
                        "PatchFilterGroup": {
                            "PatchFilters": [
                                {"Key": "PRODUCT", "Values": ["AmazonLinux2"]},
                            ]
                        },
                        "ApproveAfterDays": 7,
                        "ComplianceLevel": "UNSPECIFIED",
                        "EnableNonSecurity": False,
                    }
                ]
            },
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["BaselineId"]
        ctx.on_cleanup(lambda: ssm.delete_patch_baseline(BaselineId=baseline_id))
        return baseline_id

    baseline_id = _create_patch_baseline()

    updated = ssm.update_patch_baseline(
        BaselineId=baseline_id,
        Description="behavioral-probe-updated",
        ApprovedPatches=["kernel"],
        ApprovedPatchesComplianceLevel="HIGH",
    )
    assert updated["Description"] == "behavioral-probe-updated", updated
    assert updated["ApprovedPatches"] == ["kernel"], updated

    got = ssm.get_patch_baseline(BaselineId=baseline_id)
    assert got["Description"] == "behavioral-probe-updated", got
    assert got["ApprovedPatches"] == ["kernel"], got
    assert got["ApprovedPatchesComplianceLevel"] == "HIGH", got

    original_default = ssm.get_default_patch_baseline(
        OperatingSystem="AMAZON_LINUX_2"
    )["BaselineId"]
    try:
        ssm.register_default_patch_baseline(BaselineId=baseline_id)
        now_default = ssm.get_default_patch_baseline(
            OperatingSystem="AMAZON_LINUX_2"
        )["BaselineId"]
        assert now_default == baseline_id, (now_default, baseline_id)

        identities = ssm.describe_patch_baselines(
            Filters=[{"Key": "NAME_PREFIX", "Values": [got["Name"]]}]
        )["BaselineIdentities"]
        mine = next(b for b in identities if b["BaselineId"] == baseline_id)
        assert mine["DefaultBaseline"] is True, mine
    finally:
        ssm.register_default_patch_baseline(BaselineId=original_default)

    restored = ssm.get_default_patch_baseline(
        OperatingSystem="AMAZON_LINUX_2"
    )["BaselineId"]
    assert restored == original_default, restored


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
