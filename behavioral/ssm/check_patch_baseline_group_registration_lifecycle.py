"""patch-baseline-group-registration-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "patch-baseline-group-registration-lifecycle"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterPatchBaselineForPatchGroup associates a baseline with a group visible in
    DescribePatchGroups/DescribePatchBaselines, and Deregister removes it."""
    ssm = ctx.client("ssm")
    baseline_name = ctx.unique_name("sim2real-pb-")
    baseline_id = ssm.create_patch_baseline(
        Name=baseline_name,
        OperatingSystem="AMAZON_LINUX_2",
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )[
        "BaselineId"
    ]
    ctx.on_cleanup(lambda: ssm.delete_patch_baseline(BaselineId=baseline_id))

    patch_group = ctx.unique_name("sim2real-patchgroup-")
    registered = ssm.register_patch_baseline_for_patch_group(
        BaselineId=baseline_id, PatchGroup=patch_group
    )
    assert registered["BaselineId"] == baseline_id, registered
    assert registered["PatchGroup"] == patch_group, registered
    ctx.on_cleanup(
        lambda: _deregister_if_registered(ssm, baseline_id, patch_group)
    )

    for_group = ssm.get_patch_baseline_for_patch_group(
        PatchGroup=patch_group, OperatingSystem="AMAZON_LINUX_2"
    )
    assert for_group["BaselineId"] == baseline_id, for_group

    baseline_detail = ssm.get_patch_baseline(BaselineId=baseline_id)
    assert patch_group in baseline_detail.get("PatchGroups", []), baseline_detail

    mappings = _all_patch_group_mappings(ssm)
    match = next((m for m in mappings if m["PatchGroup"] == patch_group), None)
    assert match is not None, "patch group not visible in DescribePatchGroups"
    assert match["BaselineIdentity"]["BaselineId"] == baseline_id, match

    baselines = ssm.describe_patch_baselines(
        Filters=[{"Key": "NAME_PREFIX", "Values": [baseline_name]}]
    )["BaselineIdentities"]
    assert any(b["BaselineId"] == baseline_id for b in baselines), baselines

    ssm.deregister_patch_baseline_for_patch_group(BaselineId=baseline_id, PatchGroup=patch_group)

    mappings = _all_patch_group_mappings(ssm)
    assert not any(m["PatchGroup"] == patch_group for m in mappings), mappings

    baseline_after = ssm.get_patch_baseline(BaselineId=baseline_id)
    assert patch_group not in baseline_after.get("PatchGroups", []), baseline_after


def _all_patch_group_mappings(ssm):
    mappings = []
    next_token = None
    for _ in range(50):
        kwargs = {"NextToken": next_token} if next_token else {}
        page = ssm.describe_patch_groups(**kwargs)
        mappings.extend(page.get("Mappings", []))
        next_token = page.get("NextToken")
        if not next_token:
            break
    return mappings


def _deregister_if_registered(ssm, baseline_id: str, patch_group: str) -> None:
    ssm.deregister_patch_baseline_for_patch_group(BaselineId=baseline_id, PatchGroup=patch_group)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
