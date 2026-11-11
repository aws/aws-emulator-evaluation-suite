"""delete-patch-baseline-then-get-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-patch-baseline-then-get-fails"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """State machine: after DeletePatchBaseline, both the independent read
    (GetPatchBaseline) and a mutation (UpdatePatchBaseline) against the dead
    id must fail with DoesNotExistException."""

    ssm = ctx.client("ssm")

    def _error_code(fn):
        try:
            fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError("expected ClientError, call unexpectedly succeeded")

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
        )["BaselineId"]

    name = ctx.unique_name("sim2real-behav-probe-baseline-delete-")

    baseline_id = _create_patch_baseline(name)

    # Positive control: the baseline is live and independently readable before it is touched.
    live = ssm.get_patch_baseline(BaselineId=baseline_id)
    assert live["BaselineId"] == baseline_id, live

    ssm.delete_patch_baseline(BaselineId=baseline_id)

    code, message = _error_code(lambda: ssm.get_patch_baseline(BaselineId=baseline_id))
    assert code == "DoesNotExistException", (
        f"expected DoesNotExistException after delete, got {code!r}"
    )
    assert message == "Patch Baseline to be retrieved does not exist.", message

    # A mutation against the dead id must fail the same way, not just the read.
    update_code, update_message = _error_code(
        lambda: ssm.update_patch_baseline(BaselineId=baseline_id, Description="post-delete")
    )
    assert update_code == "DoesNotExistException", (
        f"expected DoesNotExistException on UpdatePatchBaseline after delete, got {update_code!r}"
    )
    assert update_message == "Patch Baseline to be retrieved does not exist.", update_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
