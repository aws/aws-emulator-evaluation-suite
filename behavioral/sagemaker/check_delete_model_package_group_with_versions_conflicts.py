"""delete-model-package-group-with-versions-conflicts."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-model-package-group-with-versions-conflicts"
GROUP = 'overly-permissive'
SERVICES = ['sagemaker']


# ===== helpers (self-contained) =====

def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(
        f"expected the call to be rejected, but it succeeded and returned {result!r}"
    )


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
    billable resource is created.

    Real AWS DOES validate that the
    ECR image is reachable at CreateModelPackage time -- without
    `SkipModelValidation='All'` this exact spec is refused with
    ValidationException / "Access denied for registry ID: 123456789012, repository
    name: sim2real-behav-inference. Please check if your ECR image exists and has
    proper pull permissions for SageMaker." With SkipModelValidation='All' (which every
    call in this check passes) the placeholder image is accepted, so no ECR repository
    has to be minted.
    """
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


def _group_exists(sm, group):
    summaries = sm.list_model_package_groups(
        NameContains=group, MaxResults=100
    )["ModelPackageGroupSummaryList"]
    return any(s["ModelPackageGroupName"] == group for s in summaries)


def _delete_group_quietly(sm, group):
    """Delete a model package group, tolerating it already being gone.

    The control leg at the end of the check deletes the group itself, so the registered
    teardown would otherwise fail on the second attempt. This still genuinely deletes the
    group on every path where the check stops early.
    """
    try:
        sm.delete_model_package_group(ModelPackageGroupName=group)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") in ("ValidationException", "ResourceNotFound") and (
            "not found" in (err.get("Message") or "").lower()
            or "does not exist" in (err.get("Message") or "").lower()
        ):
            return
        raise


def _delete_package_quietly(sm, arn):
    """Delete a model package version, tolerating it already being gone (see above)."""
    try:
        sm.delete_model_package(ModelPackageName=arn)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") in ("ValidationException", "ResourceNotFound") and (
            "not found" in (err.get("Message") or "").lower()
            or "does not exist" in (err.get("Message") or "").lower()
        ):
            return
        raise
# ===== end helpers =====


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A model package group with live versions refuses deletion with ValidationException naming the
    group (not the modelled ConflictException), identically by name and by ARN; the group and version
    survive, and deleting the version first lets the group delete.
    """
    sm = ctx.client("sagemaker")
    timeout_s = 180

    group = ctx.unique_name("sim2real-behav-mpg-")
    group_arn = sm.create_model_package_group(
        ModelPackageGroupName=group,
        ModelPackageGroupDescription="behav registry group",
    )["ModelPackageGroupArn"]
    # Registered first => deleted last (LIFO), which is the only order that can
    # succeed: the group delete is refused while a version exists.
    ctx.on_cleanup(lambda: _delete_group_quietly(sm, group))
    assert group_arn.endswith("model-package-group/%s" % group), (
        f"CreateModelPackageGroup returned an ARN that does not name the group: {group_arn}"
    )
    arn = sm.create_model_package(
        ModelPackageGroupName=group,
        InferenceSpecification=_inference_spec(ctx),
        SkipModelValidation="All",
    )["ModelPackageArn"]
    ctx.on_cleanup(lambda: _delete_package_quietly(sm, arn))
    desc = _poll(
        lambda: sm.describe_model_package(ModelPackageName=arn),
        lambda d: d["ModelPackageStatus"] in ("Completed", "Failed"),
        timeout_s=timeout_s,
    )
    assert desc["ModelPackageStatus"] == "Completed", desc["ModelPackageStatus"]

    # The refusal names the group by ARN even when the request named it by string.
    expected_message = (
        "Model Package Group %s cannot be deleted because it still contains Model "
        "Packages." % group_arn
    )

    # Break exactly one thing: delete the parent while the child lives.
    for what, identifier in (("name", group), ("ARN", group_arn)):
        code, message = _error(
            lambda i=identifier: sm.delete_model_package_group(ModelPackageGroupName=i)
        )
        assert code == "ValidationException", (
            f"DeleteModelPackageGroup by {what} with a live version returned code={code!r}; "
            f"real AWS returns ValidationException (the Smithy model declares only "
            f"ConflictException, and real AWS is the arbiter); message={message!r}"
        )
        assert message == expected_message, (
            f"the refusal (by {what}) must state that the group still contains model "
            f"packages and name the group: expected {expected_message!r}, got {message!r}"
        )

    # Effect absent, on both sides of the reference.
    assert _group_exists(sm, group), (
        f"group {group} disappeared despite the refused delete"
    )
    survived = sm.describe_model_package(ModelPackageName=arn)
    assert survived["ModelPackageArn"] == arn, survived
    assert survived["ModelPackageStatus"] == "Completed", (
        f"version status changed after the refused group delete: "
        f"{survived['ModelPackageStatus']}"
    )
    still_listed = [
        s["ModelPackageArn"]
        for s in sm.list_model_packages(
            ModelPackageGroupName=group, MaxResults=100
        )["ModelPackageSummaryList"]
    ]
    assert still_listed == [arn], (
        f"the refused group delete changed the group's membership: {still_listed}, "
        f"expected exactly [{arn}]"
    )

    # Control: correct order (child, then parent) succeeds.
    sm.delete_model_package(ModelPackageName=arn)
    gone = _poll(
        lambda: sm.list_model_packages(
            ModelPackageGroupName=group, MaxResults=100
        )["ModelPackageSummaryList"],
        lambda summaries: summaries == [],
        timeout_s=timeout_s,
    )
    assert gone == [], f"version still listed after DeleteModelPackage: {gone}"

    # A second, independent op (describe, not list) must also see the version gone.
    pkg_gone_code, pkg_gone_message = _error(
        lambda: sm.describe_model_package(ModelPackageName=arn)
    )
    assert pkg_gone_code == "ValidationException", (
        f"DescribeModelPackage on a deleted version returned code={pkg_gone_code!r} "
        f"message={pkg_gone_message!r}; expected ValidationException"
    )
    expected_pkg_gone = f"ModelPackage {arn} does not exist."
    assert pkg_gone_message == expected_pkg_gone, (
        f"expected {expected_pkg_gone!r}, got {pkg_gone_message!r}"
    )

    sm.delete_model_package_group(ModelPackageGroupName=group)
    absent = _poll(
        lambda: _group_exists(sm, group),
        lambda exists: not exists,
        timeout_s=timeout_s,
    )
    assert absent is False, (
        f"group {group} still listed after the control delete succeeded"
    )

    # A second, independent op (describe, not list) must also see the group gone.
    group_gone_code, group_gone_message = _error(
        lambda: sm.describe_model_package_group(ModelPackageGroupName=group)
    )
    assert group_gone_code == "ValidationException", (
        f"DescribeModelPackageGroup on a deleted group returned code={group_gone_code!r} "
        f"message={group_gone_message!r}; expected ValidationException"
    )
    expected_group_gone = f"ModelPackageGroup {group_arn} does not exist."
    assert group_gone_message == expected_group_gone, (
        f"expected {expected_group_gone!r}, got {group_gone_message!r}"
    )

    # A mutation on the dead group id must also fail, not succeed as a no-op.
    double_delete_code, double_delete_message = _error(
        lambda: sm.delete_model_package_group(ModelPackageGroupName=group)
    )
    assert double_delete_code == "ValidationException", (
        f"DeleteModelPackageGroup a second time on an already-deleted group {group} "
        f"returned code={double_delete_code!r} message={double_delete_message!r}; "
        f"expected ValidationException"
    )
    expected_double_delete = f"ModelPackageGroup {group_arn} does not exist."
    assert double_delete_message == expected_double_delete, (
        f"expected {expected_double_delete!r}, got {double_delete_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
