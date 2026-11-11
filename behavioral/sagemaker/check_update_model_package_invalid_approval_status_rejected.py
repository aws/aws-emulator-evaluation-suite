"""update-model-package-invalid-approval-status-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-model-package-invalid-approval-status-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sagemaker']


def _error(fn):
    """Return (code, message) for a ClientError. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll(fn, pred, *, timeout_s, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _inference_spec(ctx):
    """Registration-only InferenceSpecification -- nothing is pulled or run, so no
    billable resource is created."""
    return {
        "Containers": [
            {
                "Image": (
                    "123456789012.dkr.ecr.%s.amazonaws.com/"
                    "sim2real-behav-inference:latest" % ctx.region
                ),
            }
        ],
        "SupportedContentTypes": ["text/csv"],
    }


def _registered_version(ctx, *, approval, timeout_s):
    """Create a group + one Completed version inside it, cleanup-safe."""
    sm = ctx.client("sagemaker")
    group = ctx.unique_name("sim2real-behav-mpg-")
    sm.create_model_package_group(ModelPackageGroupName=group)
    # First registration => last deletion (LIFO): the group cannot be deleted
    # while a version still exists.
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=group))
    arn = sm.create_model_package(
        ModelPackageGroupName=group,
        InferenceSpecification=_inference_spec(ctx),
        SkipModelValidation="All",
        ModelApprovalStatus=approval,
    )["ModelPackageArn"]
    ctx.on_cleanup(lambda: sm.delete_model_package(ModelPackageName=arn))
    desc = _poll(
        lambda: sm.describe_model_package(ModelPackageName=arn),
        lambda d: d["ModelPackageStatus"] in ("Completed", "Failed"),
        timeout_s=timeout_s,
    )
    assert desc["ModelPackageStatus"] == "Completed", (
        f"{arn} did not reach Completed: {desc['ModelPackageStatus']}"
    )
    return group, arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateModelPackage with an out-of-enum ModelApprovalStatus is refused with ValidationException
    (exact message) and the package stays PendingManualApproval and Completed; a valid update to
    Approved is stored, and ListModelPackages(Approved) returns only this package.
    """
    sm = ctx.client("sagemaker")
    group, arn = _registered_version(ctx, approval="PendingManualApproval", timeout_s=180)

    for bad in ("Maybe", "approved", "APPROVED", ""):
        code, message = _error(
            lambda: sm.update_model_package(
                ModelPackageArn=arn, ModelApprovalStatus=bad
            )
        )
        assert code == "ValidationException", (
            f"UpdateModelPackage accepted ModelApprovalStatus={bad!r} "
            f"(code={code}) -- an approval gate built on this value is worthless"
        )
        expected = (
            f"1 validation error detected: Value '{bad}' at 'modelApprovalStatus' failed to "
            "satisfy constraint: Member must satisfy enum value set: "
            "[PendingManualApproval, Approved, Rejected]"
        )
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the stored status is untouched by every rejected update.
    still = sm.describe_model_package(ModelPackageName=arn)
    assert still["ModelApprovalStatus"] == "PendingManualApproval", (
        f"rejected update mutated state: {still.get('ModelApprovalStatus')}"
    )
    assert still["ModelPackageStatus"] == "Completed", still["ModelPackageStatus"]

    # Control: the valid transition on the same resource still works.
    sm.update_model_package(ModelPackageArn=arn, ModelApprovalStatus="Approved")
    after = sm.describe_model_package(ModelPackageName=arn)
    assert after["ModelApprovalStatus"] == "Approved", (
        f"control transition failed after rejections: "
        f"{after.get('ModelApprovalStatus')}"
    )
    listed = sm.list_model_packages(
        ModelPackageGroupName=group,
        ModelApprovalStatus="Approved",
        MaxResults=100,
    )["ModelPackageSummaryList"]
    assert [s["ModelPackageArn"] for s in listed] == [arn], listed


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
