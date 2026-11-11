"""describe-effective-patches-nonexistent-baseline-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-effective-patches-nonexistent-baseline-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeEffectivePatchesForPatchBaseline answers for a real baseline but fails with
    DoesNotExistException "Patch Baseline to be retrieved does not exist." for an unknown id and for
    the baseline's own id after deletion."""
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
                        ]
                    },
                    "ApproveAfterDays": 7,
                }
            ]
        },
    )
    baseline_id = created["BaselineId"]
    ctx.on_cleanup(lambda: _delete_if_present(ssm, baseline_id))

    # Positive control: the real baseline resolves without error.
    control = ssm.describe_effective_patches_for_patch_baseline(BaselineId=baseline_id)
    assert "EffectivePatches" in control, (
        f"positive control against real baseline {baseline_id!r} did not return "
        f"EffectivePatches: {control!r}"
    )

    # Negative: a well-formed but nonexistent baseline id.
    bogus_id = "pb-00000000000000000"
    code, message = _error(
        lambda: ssm.describe_effective_patches_for_patch_baseline(BaselineId=bogus_id)
    )
    assert code == "DoesNotExistException", (
        f"a syntactically valid but unknown BaselineId {bogus_id!r} was rejected with "
        f"{code!r}, expected 'DoesNotExistException'"
    )
    assert message == "Patch Baseline to be retrieved does not exist.", message

    # The real baseline's own id, once deleted, must be rejected the identical
    # way -- proving the refusal is not limited to ids that were never real.
    ssm.delete_patch_baseline(BaselineId=baseline_id)
    code_after_delete, message_after_delete = _error(
        lambda: ssm.describe_effective_patches_for_patch_baseline(BaselineId=baseline_id)
    )
    assert code_after_delete == "DoesNotExistException", (
        f"the deleted baseline {baseline_id!r} was rejected with "
        f"{code_after_delete!r}, expected 'DoesNotExistException'"
    )
    assert message_after_delete == "Patch Baseline to be retrieved does not exist.", (
        message_after_delete
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _delete_if_present(ssm, baseline_id):
    try:
        ssm.delete_patch_baseline(BaselineId=baseline_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "DoesNotExistException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
