"""describe-effective-patches-unknown-baseline-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-effective-patches-unknown-baseline-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeEffectivePatchesForPatchBaseline on a nonexistent baseline raises
    DoesNotExistException, while the same call against a real baseline succeeds."""
    ssm = ctx.client("ssm")
    name = ctx.unique_name("sim2real-ssm-pb-")
    # CreatePatchBaseline requires at least one non-empty ApprovedPatches or
    # ApprovalRules -- an all-defaults baseline is rejected with ValidationException.
    baseline_id = ssm.create_patch_baseline(
        Name=name,
        ApprovedPatches=["KB0000001"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["BaselineId"]
    ctx.on_cleanup(lambda: ssm.delete_patch_baseline(BaselineId=baseline_id))

    # Positive control: a real baseline resolves fine (may have zero effective patches).
    positive = ssm.describe_effective_patches_for_patch_baseline(BaselineId=baseline_id)
    assert "EffectivePatches" in positive, (
        f"positive control on a real baseline is missing EffectivePatches: {positive!r}"
    )

    # Negative: a well-formed but nonexistent BaselineId is rejected distinctly.
    # Derive it from the real baseline_id (same length/format) so it passes shape
    # validation and only fails existence validation.
    fake_baseline_id = baseline_id[:-1] + ("0" if baseline_id[-1] != "0" else "1")

    def _call():
        ssm.describe_effective_patches_for_patch_baseline(BaselineId=fake_baseline_id)

    code, message = _error(_call)
    assert code == "DoesNotExistException", f"expected DoesNotExistException, got {code}"
    assert message == "Patch Baseline to be retrieved does not exist.", message


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING an id real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(
        f"expected DescribeEffectivePatchesForPatchBaseline to reject the unknown baseline id, "
        f"but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
