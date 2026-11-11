"""describe-effective-patches-for-baseline-reflects-rules."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-effective-patches-for-baseline-reflects-rules"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeEffectivePatchesForPatchBaseline resolves the patches matching the
    baseline's ApprovalRules (a PRODUCT + CLASSIFICATION filter), immediately
    approving them when ApproveAfterDays=0 for historical (already-released) patches.
    """
    ssm = ctx.client("ssm")
    name = ctx.unique_name("sim2real-behav-patchbase-")
    created = ssm.create_patch_baseline(
        Name=name,
        OperatingSystem="WINDOWS",
        ApprovalRules={
            "PatchRules": [
                {
                    "PatchFilterGroup": {
                        "PatchFilters": [
                            {"Key": "PRODUCT", "Values": ["WindowsServer2012"]},
                            {"Key": "CLASSIFICATION", "Values": ["SecurityUpdates"]},
                        ]
                    },
                    "ApproveAfterDays": 0,
                    "ComplianceLevel": "CRITICAL",
                }
            ]
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    baseline_id = created["BaselineId"]
    ctx.on_cleanup(lambda: ssm.delete_patch_baseline(BaselineId=baseline_id))

    effective_patches = []
    next_token = None
    while True:
        kwargs = {"BaselineId": baseline_id, "MaxResults": 100}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = ssm.describe_effective_patches_for_patch_baseline(**kwargs)
        effective_patches.extend(resp["EffectivePatches"])
        next_token = resp.get("NextToken")
        if not next_token:
            break

    assert len(effective_patches) > 0, "expected at least one effective patch for the approval rule"
    for entry in effective_patches:
        patch = entry["Patch"]
        assert patch["Product"] == "WindowsServer2012", patch["Product"]
        assert patch["Classification"] == "SecurityUpdates", patch["Classification"]
        # ApproveAfterDays=0 against already-released historical patches -> immediately approved.
        assert entry["PatchStatus"]["DeploymentStatus"] == "APPROVED", entry["PatchStatus"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
