"""model-package-approval-status-transitions."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "model-package-approval-status-transitions"
GROUP = 'lifecycle'
SERVICES = ['sagemaker']


# ===== helpers (self-contained) =====

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
    billable resource is created. Confirmed against real AWS: CreateModelPackage
    does not validate ECR image existence at registration time, so a fabricated
    repo/tag in another account registers cleanly."""
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
        "SupportedResponseMIMETypes": ["text/csv"],
    }


def _create_model_package_group(ctx):
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-behav-mpg-")
    sm.create_model_package_group(
        ModelPackageGroupName=name,
        ModelPackageGroupDescription="behav registry group",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    # Registered first => LIFO deletes it last, after the versions inside it.
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=name))
    # Versions can't carry their own Tags (real AWS: "Tags are not supported in
    # Model Package versions. Please add them to the Model Package Group."), so
    # the group tag is what a tag search finds; versions are its children.
    return name


def _register_version(ctx, group, **extra):
    sm = ctx.client("sagemaker")
    kwargs = {
        "ModelPackageGroupName": group,
        "InferenceSpecification": _inference_spec(ctx),
        "SkipModelValidation": "All",
    }
    kwargs.update(extra)
    arn = sm.create_model_package(**kwargs)["ModelPackageArn"]
    ctx.on_cleanup(lambda: sm.delete_model_package(ModelPackageName=arn))
    return arn


def _wait_terminal(ctx, arn, *, timeout_s):
    sm = ctx.client("sagemaker")
    desc = _poll(
        lambda: sm.describe_model_package(ModelPackageName=arn),
        lambda d: d["ModelPackageStatus"] in ("Completed", "Failed"),
        timeout_s=timeout_s,
    )
    assert desc["ModelPackageStatus"] == "Completed", (
        f"{arn} did not reach Completed: {desc['ModelPackageStatus']}"
    )
    return desc
# ===== end helpers =====


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PendingManualApproval -> Approved -> Rejected are each accepted, persist ApprovalDescription and
    advance LastModifiedTime without disturbing ModelPackageStatus: CI/CD gates read
    ModelApprovalStatus to decide whether to deploy.
    """
    sm = ctx.client("sagemaker")
    timeout_s = 180
    group = _create_model_package_group(ctx)

    arn = _register_version(
        ctx, group, ModelApprovalStatus="PendingManualApproval"
    )
    desc = _wait_terminal(ctx, arn, timeout_s=timeout_s)
    assert desc["ModelApprovalStatus"] == "PendingManualApproval", (
        f"initial approval status not honoured: {desc.get('ModelApprovalStatus')}"
    )
    first_modified = desc.get("LastModifiedTime")

    # PendingManualApproval -> Approved, with a description that must persist.
    out = sm.update_model_package(
        ModelPackageArn=arn,
        ModelApprovalStatus="Approved",
        ApprovalDescription="approved by sim2real behavioral check",
    )
    assert out["ModelPackageArn"] == arn, out
    approved = sm.describe_model_package(ModelPackageName=arn)
    assert approved["ModelApprovalStatus"] == "Approved", (
        f"transition to Approved not persisted: {approved.get('ModelApprovalStatus')}"
    )
    assert (
        approved.get("ApprovalDescription")
        == "approved by sim2real behavioral check"
    ), f"ApprovalDescription not persisted: {approved.get('ApprovalDescription')!r}"
    assert approved["ModelPackageStatus"] == "Completed", (
        f"approval must not disturb ModelPackageStatus: "
        f"{approved['ModelPackageStatus']}"
    )
    second_modified = approved.get("LastModifiedTime")
    assert second_modified is not None, "LastModifiedTime missing after update"
    if first_modified is not None:
        assert second_modified >= first_modified, (
            f"LastModifiedTime went backwards: {first_modified} -> {second_modified}"
        )

    # Approved -> Rejected is a legal transition; the description is replaced.
    sm.update_model_package(
        ModelPackageArn=arn,
        ModelApprovalStatus="Rejected",
        ApprovalDescription="rejected by sim2real behavioral check",
    )
    rejected = sm.describe_model_package(ModelPackageName=arn)
    assert rejected["ModelApprovalStatus"] == "Rejected", (
        f"transition to Rejected not persisted: {rejected.get('ModelApprovalStatus')}"
    )
    assert (
        rejected.get("ApprovalDescription")
        == "rejected by sim2real behavioral check"
    ), f"ApprovalDescription not replaced: {rejected.get('ApprovalDescription')!r}"

    # The status is a queryable projection, not just a Describe field.
    summaries = sm.list_model_packages(
        ModelPackageGroupName=group,
        ModelApprovalStatus="Rejected",
        MaxResults=100,
    )["ModelPackageSummaryList"]
    assert [s["ModelPackageArn"] for s in summaries] == [arn], (
        f"ListModelPackages(ModelApprovalStatus='Rejected') returned "
        f"{[s['ModelPackageArn'] for s in summaries]}"
    )
    not_approved = sm.list_model_packages(
        ModelPackageGroupName=group,
        ModelApprovalStatus="Approved",
        MaxResults=100,
    )["ModelPackageSummaryList"]
    assert not_approved == [], (
        f"stale Approved projection after Rejected: {not_approved}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
