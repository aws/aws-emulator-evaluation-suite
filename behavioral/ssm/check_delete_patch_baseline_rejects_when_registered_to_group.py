"""delete-patch-baseline-rejects-when-registered-to-group."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-patch-baseline-rejects-when-registered-to-group"
GROUP = 'overly-permissive'
SERVICES = ['ssm']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePatchBaseline on a baseline registered to a patch group fails with ResourceInUseException naming
    the group and the baseline stays; after deregistration the delete succeeds and GetPatchBaseline fails
    with DoesNotExistException."""

    ssm = ctx.client("ssm")

    def _error(fn):
        """Call fn(); return its error (code, message). An unexpected SUCCESS raises, so an
        emulator that accepts what AWS refuses cannot read as a code mismatch."""
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message", "")
        raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")

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
            Tags=[{"Key": "sim2real-behav-probe", "Value": name}],
        )["BaselineId"]

        def _delete_if_present():
            try:
                ssm.delete_patch_baseline(BaselineId=baseline_id)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "DoesNotExistException":
                    raise

        ctx.on_cleanup(_delete_if_present)
        return baseline_id

    baseline_id = _create_patch_baseline()
    patch_group = ctx.unique_name("sim2real-behav-pg-")
    ssm.register_patch_baseline_for_patch_group(
        BaselineId=baseline_id, PatchGroup=patch_group
    )

    code, message = _error(lambda: ssm.delete_patch_baseline(BaselineId=baseline_id))
    assert code == "ResourceInUseException", code
    assert message == f"PatchBaseline to be deleted is used for Patch Group: {patch_group}", message

    # Still intact after the rejected delete.
    still_there = ssm.get_patch_baseline(BaselineId=baseline_id)
    assert still_there["BaselineId"] == baseline_id, still_there

    ssm.deregister_patch_baseline_for_patch_group(
        BaselineId=baseline_id, PatchGroup=patch_group
    )

    # Restore leg: the identical delete call succeeds once the blocking
    # registration is gone.
    ssm.delete_patch_baseline(BaselineId=baseline_id)
    code_after, message_after = _error(lambda: ssm.get_patch_baseline(BaselineId=baseline_id))
    assert code_after == "DoesNotExistException", (
        f"expected DoesNotExistException after the restored delete, got {code_after!r}"
    )
    assert message_after == "Patch Baseline to be retrieved does not exist.", message_after

    # DeletePatchBaseline is idempotent: a second delete of the deleted
    # baseline is a clean no-op success, so any ClientError here fails the check.
    ssm.delete_patch_baseline(BaselineId=baseline_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
