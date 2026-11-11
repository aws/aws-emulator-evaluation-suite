"""default-patch-baseline-register-and-update."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "default-patch-baseline-register-and-update"
GROUP = "state-machine"
SERVICES = ["ssm"]

_OS = "DEBIAN"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ssm-default-patch-baseline")
def run(ctx) -> None:
    """RegisterDefaultPatchBaseline sets the OS default returned by
    GetDefaultPatchBaseline, and UpdatePatchBaseline mutates baseline attributes."""
    ssm = ctx.client("ssm")
    original_default = ssm.get_default_patch_baseline(OperatingSystem=_OS)["BaselineId"]

    baseline_name = ctx.unique_name("sim2real-defpb-")
    new_id = ssm.create_patch_baseline(
        Name=baseline_name,
        OperatingSystem=_OS,
        ApprovalRules={
            "PatchRules": [
                {
                    "PatchFilterGroup": {
                        "PatchFilters": [{"Key": "PRODUCT", "Values": ["*"]}]
                    },
                    "ApproveAfterDays": 7,
                }
            ]
        },
    )["BaselineId"]

    def _restore_and_delete():
        ssm.register_default_patch_baseline(BaselineId=original_default)
        ssm.delete_patch_baseline(BaselineId=new_id)

    ctx.on_cleanup(_restore_and_delete)

    ssm.register_default_patch_baseline(BaselineId=new_id)
    current_default = ssm.get_default_patch_baseline(OperatingSystem=_OS)["BaselineId"]
    assert current_default == new_id, f"expected default {new_id!r}, got {current_default!r}"

    identities = ssm.describe_patch_baselines(
        Filters=[{"Key": "NAME_PREFIX", "Values": [baseline_name]}]
    )["BaselineIdentities"]
    mine = next(b for b in identities if b["BaselineId"] == new_id)
    assert mine["DefaultBaseline"] is True, f"expected DefaultBaseline=True, got {mine!r}"

    updated = ssm.update_patch_baseline(BaselineId=new_id, Description="sim2real-updated-description")
    assert updated["Description"] == "sim2real-updated-description", (
        f"expected updated Description 'sim2real-updated-description', got {updated!r}"
    )

    fetched = ssm.get_patch_baseline(BaselineId=new_id)
    assert fetched["Description"] == "sim2real-updated-description", (
        f"expected Description 'sim2real-updated-description', got {fetched!r}"
    )
    assert fetched["Name"] == baseline_name, f"expected Name {baseline_name!r}, got {fetched!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
