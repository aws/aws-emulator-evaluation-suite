"""register-patch-baseline-for-patch-group-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-patch-baseline-for-patch-group-conflict-rejected"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Registering a patch group already mapped to another baseline fails with
    AlreadyExistsException and the exact message and keeps the mapping; after deregistration the
    same call succeeds and the group resolves to the second baseline."""
    ssm = ctx.client("ssm")
    approval_rules = {
        "PatchRules": [
            {
                "PatchFilterGroup": {
                    "PatchFilters": [{"Key": "PRODUCT", "Values": ["*"]}]
                },
                "ApproveAfterDays": 7,
            }
        ]
    }
    baseline_a = ssm.create_patch_baseline(
        Name=ctx.unique_name("sim2real-pb-a-"),
        OperatingSystem="AMAZON_LINUX_2",
        ApprovalRules=approval_rules,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["BaselineId"]
    ctx.on_cleanup(lambda: ssm.delete_patch_baseline(BaselineId=baseline_a))
    baseline_b = ssm.create_patch_baseline(
        Name=ctx.unique_name("sim2real-pb-b-"),
        OperatingSystem="AMAZON_LINUX_2",
        ApprovalRules=approval_rules,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["BaselineId"]
    ctx.on_cleanup(lambda: ssm.delete_patch_baseline(BaselineId=baseline_b))

    patch_group = ctx.unique_name("sim2real-patchgroup-")
    ssm.register_patch_baseline_for_patch_group(BaselineId=baseline_a, PatchGroup=patch_group)
    ctx.on_cleanup(
        lambda: _deregister_if_registered(ssm, baseline_a, patch_group)
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

    # Effect absent: the rejected duplicate registration did not move the mapping.
    current = ssm.get_patch_baseline_for_patch_group(
        PatchGroup=patch_group, OperatingSystem="AMAZON_LINUX_2"
    )
    assert current["BaselineId"] == baseline_a, current["BaselineId"]

    # Restore: freeing the group of its original mapping makes the identical call succeed.
    ssm.deregister_patch_baseline_for_patch_group(BaselineId=baseline_a, PatchGroup=patch_group)
    ssm.register_patch_baseline_for_patch_group(BaselineId=baseline_b, PatchGroup=patch_group)
    ctx.on_cleanup(
        lambda: _deregister_if_registered(ssm, baseline_b, patch_group)
    )
    restored = ssm.get_patch_baseline_for_patch_group(
        PatchGroup=patch_group, OperatingSystem="AMAZON_LINUX_2"
    )
    assert restored["BaselineId"] == baseline_b, restored["BaselineId"]


def _deregister_if_registered(ssm, baseline_id: str, patch_group: str) -> None:
    ssm.deregister_patch_baseline_for_patch_group(BaselineId=baseline_id, PatchGroup=patch_group)


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
