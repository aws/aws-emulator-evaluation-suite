"""create-patch-baseline-and-get."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-patch-baseline-and-get"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePatchBaseline returns a BaselineId that GetPatchBaseline resolves with matching Name."""

    ssm = ctx.client("ssm")

    def _track_baseline(baseline_id):
        ctx.on_cleanup(lambda: ssm.delete_patch_baseline(BaselineId=baseline_id))
        return baseline_id

    def _create_patch_baseline(name):
        # Real SSM rejects CreatePatchBaseline unless ApprovedPatches or ApprovalRules
        # is non-empty, so supply an explicit approval rule.
        return ssm.create_patch_baseline(
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
            Tags=[{"Key": "sim2real-behav-probe", "Value": name}],
        )["BaselineId"]

    name = ctx.unique_name("sim2real-behav-probe-baseline-")

    baseline_id = _create_patch_baseline(name)
    _track_baseline(baseline_id)

    got = ssm.get_patch_baseline(BaselineId=baseline_id)
    assert got["Name"] == name, f"expected Name {name!r}, got {got['Name']!r}"
    assert got["BaselineId"] == baseline_id, (
        f"expected BaselineId {baseline_id!r}, got {got['BaselineId']!r}"
    )
    assert got["OperatingSystem"] == "AMAZON_LINUX_2", (
        f"expected OperatingSystem AMAZON_LINUX_2, got {got['OperatingSystem']!r}"
    )
    rules = got["ApprovalRules"]["PatchRules"]
    assert len(rules) == 1, f"expected 1 approval rule, got {len(rules)}"
    rule = rules[0]
    assert rule["ApproveAfterDays"] == 7, (
        f"expected ApproveAfterDays 7, got {rule['ApproveAfterDays']!r}"
    )
    filters = rule["PatchFilterGroup"]["PatchFilters"]
    assert filters == [{"Key": "PRODUCT", "Values": ["AmazonLinux2"]}], (
        f"expected the submitted PRODUCT filter to round-trip, got {filters!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
