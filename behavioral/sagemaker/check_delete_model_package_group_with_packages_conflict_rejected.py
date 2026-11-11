"""delete-model-package-group-with-packages-conflict-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-model-package-group-with-packages-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]

_DELETE_TIMEOUT_S = 120.0


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteModelPackageGroup rejects a group that still holds a model package with the exact
    ValidationException and keeps both; once ListModelPackages shows the group empty the same
    delete succeeds and the group is gone.
    """
    sm = ctx.client("sagemaker")
    group_name = ctx.unique_name("sim2real-mpg-conflict-")

    sm.create_model_package_group(ModelPackageGroupName=group_name)
    ctx.on_cleanup(lambda: _delete_group_quiet(sm, group_name))

    # No InferenceSpecification: CreateModelPackage validates that a referenced ECR
    # image actually exists, and a versioned package can be registered with only
    # metadata (the spec can be filled in later via UpdateModelPackage) while still
    # producing a real, non-empty group.
    package_arn = sm.create_model_package(
        ModelPackageGroupName=group_name,
        ModelApprovalStatus="PendingManualApproval",
        ModelPackageDescription="sim2real behavioral probe placeholder version",
    )["ModelPackageArn"]
    ctx.on_cleanup(lambda: _delete_package_quiet(sm, package_arn))

    group_arn = f"arn:aws:sagemaker:{ctx.region}:{ctx.account}:model-package-group/{group_name}"
    code, message = _error_code_and_message(
        lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    expected_message = (
        f"Model Package Group {group_arn} cannot be deleted because it still contains "
        "Model Packages."
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # (b) effect absent: the group (and its package) must still exist.
    desc = sm.describe_model_package_group(ModelPackageGroupName=group_name)
    assert desc["ModelPackageGroupName"] == group_name, (
        f"expected group {group_name!r} to survive the rejected delete, "
        f"got {desc.get('ModelPackageGroupName')!r}"
    )
    pkg_desc = sm.describe_model_package(ModelPackageName=package_arn)
    assert pkg_desc["ModelPackageArn"] == package_arn, (
        f"expected package {package_arn!r} to survive the rejected delete, "
        f"got {pkg_desc.get('ModelPackageArn')!r}"
    )

    # (c) positive control: once the group is actually empty, the same delete succeeds.
    # DeleteModelPackage documents no synchronous removal, so wait until the group lists empty.
    sm.delete_model_package(ModelPackageName=package_arn)
    remaining = _poll(
        ctx,
        lambda: sm.list_model_packages(ModelPackageGroupName=group_name, MaxResults=100)[
            "ModelPackageSummaryList"
        ],
        lambda summaries: summaries == [],
    )
    assert remaining == [], f"package still listed after DeleteModelPackage: {remaining}"
    sm.delete_model_package_group(ModelPackageGroupName=group_name)

    not_found_code, not_found_message = _poll_group_gone(ctx, sm, group_name)
    assert not_found_code == "ValidationException", (
        f"expected ValidationException, got {not_found_code}: {not_found_message!r}"
    )
    expected_gone = f"ModelPackageGroup {group_arn} does not exist."
    assert not_found_message == expected_gone, (
        f"expected {expected_gone!r}, got {not_found_message!r}"
    )


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it succeeded and returned {result!r}"
    )


def _poll_group_gone(ctx, sm, group_name: str):
    """(code, message) once DescribeModelPackageGroup is refused; still describable at the deadline raises."""
    budget_s = _budget_s(ctx, _DELETE_TIMEOUT_S)
    start = time.monotonic()
    stop = start + min(_DELETE_TIMEOUT_S, budget_s)
    while True:
        try:
            sm.describe_model_package_group(ModelPackageGroupName=group_name)
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        if time.monotonic() >= stop:
            if budget_s < _DELETE_TIMEOUT_S:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
                    f"{_DELETE_TIMEOUT_S}s deletion wait ended; not graded"
                )
            raise AssertionError(
                f"model package group {group_name!r} is still describable after DeleteModelPackageGroup"
            )
        time.sleep(3.0)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll(ctx, probe, predicate):
    """probe() until predicate holds or the budget ends; returns the last value."""
    budget_s = _budget_s(ctx, _DELETE_TIMEOUT_S)
    start = time.monotonic()
    stop = start + min(_DELETE_TIMEOUT_S, budget_s)
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= stop:
            if budget_s < _DELETE_TIMEOUT_S:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
                    f"{_DELETE_TIMEOUT_S}s wait ended (last={last!r}); not graded"
                )
            return last
        time.sleep(3.0)


def _gone(exc: ClientError) -> bool:
    """SageMaker reports a missing model package or group as a ValidationException."""
    err = exc.response["Error"]
    return err["Code"] == "ValidationException" and "does not exist" in err.get("Message", "")


def _delete_package_quiet(sm, package_arn: str) -> None:
    try:
        sm.delete_model_package(ModelPackageName=package_arn)
    except ClientError as exc:
        if not _gone(exc):
            raise


def _delete_group_quiet(sm, name: str) -> None:
    """Delete the group, retrying while a just-deleted package still holds it; the last failure raises."""
    deadline = time.monotonic() + _DELETE_TIMEOUT_S
    while True:
        try:
            sm.delete_model_package_group(ModelPackageGroupName=name)
            return
        except ClientError as exc:
            if _gone(exc):
                return
            holding = "still contains Model Packages" in exc.response["Error"].get("Message", "")
            if not holding or time.monotonic() >= deadline:
                raise
        time.sleep(3.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
