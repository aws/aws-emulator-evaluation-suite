"""patch-group-registration-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "patch-group-registration-lifecycle"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Registering/deregistering a patch group rewires GetPatchBaselineForPatchGroup."""

    ssm = ctx.client("ssm")

    def _error_code(fn):
        """Call fn(); return its (error code, message). An unexpected SUCCESS raises, because an
        emulator ACCEPTING input real AWS refuses is the strongest signal available."""
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError(f"expected a ClientError but the call SUCCEEDED and returned {result!r}")

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
    patch_group = ctx.unique_name("sim2real-behav-pg-")

    reg = ssm.register_patch_baseline_for_patch_group(
        BaselineId=baseline_id, PatchGroup=patch_group
    )
    assert reg["BaselineId"] == baseline_id, reg
    assert reg["PatchGroup"] == patch_group, reg

    resolved = ssm.get_patch_baseline_for_patch_group(
        PatchGroup=patch_group, OperatingSystem="AMAZON_LINUX_2"
    )
    assert resolved["BaselineId"] == baseline_id, resolved

    baseline = ssm.get_patch_baseline(BaselineId=baseline_id)
    assert patch_group in baseline.get("PatchGroups", []), baseline

    groups = ssm.describe_patch_groups()["Mappings"]
    mapping = next(m for m in groups if m["PatchGroup"] == patch_group)
    assert mapping["BaselineIdentity"]["BaselineId"] == baseline_id, mapping

    # Registering the same group to a second baseline must be rejected.
    other_baseline = _create_patch_baseline()
    dup_code, dup_message = _error_code(
        lambda: ssm.register_patch_baseline_for_patch_group(
            BaselineId=other_baseline, PatchGroup=patch_group
        )
    )
    assert dup_code == "AlreadyExistsException", dup_code
    assert dup_message == (
        f"Patch Group {patch_group} already has a baseline registered for OperatingSystem AMAZON_LINUX_2."
    ), dup_message

    ssm.deregister_patch_baseline_for_patch_group(
        BaselineId=baseline_id, PatchGroup=patch_group
    )
    groups_after = ssm.describe_patch_groups()["Mappings"]
    assert all(m["PatchGroup"] != patch_group for m in groups_after), groups_after
    baseline_after = ssm.get_patch_baseline(BaselineId=baseline_id)
    assert patch_group not in baseline_after.get("PatchGroups", []), baseline_after

    # Deregistration frees the patch group name: it is reusable, and the AlreadyExistsException
    # above was about the live mapping, not the name itself.
    reused = ssm.register_patch_baseline_for_patch_group(
        BaselineId=other_baseline, PatchGroup=patch_group
    )
    assert reused["BaselineId"] == other_baseline, reused
    ctx.on_cleanup(
        lambda: ssm.deregister_patch_baseline_for_patch_group(
            BaselineId=other_baseline, PatchGroup=patch_group
        )
    )
    final = ssm.get_patch_baseline_for_patch_group(
        PatchGroup=patch_group, OperatingSystem="AMAZON_LINUX_2"
    )
    assert final["BaselineId"] == other_baseline, final


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
