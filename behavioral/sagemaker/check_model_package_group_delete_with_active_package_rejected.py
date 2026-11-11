"""model-package-group-delete-with-active-package-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-package-group-delete-with-active-package-rejected"
GROUP = "e2e"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteModelPackageGroup on a group holding a package version is rejected and both survive;
    once the package is removed the same delete succeeds (positive control), and a repeat
    delete on the gone group fails."""
    sm = ctx.client("sagemaker")

    check_tag = [{"Key": "sim2real", "Value": CHECK}]

    group_name = ctx.unique_name("sim2real-mpg-")
    group_arn = sm.create_model_package_group(
        ModelPackageGroupName=group_name, Tags=check_tag
    )["ModelPackageGroupArn"]

    def _cleanup_group() -> None:
        _delete_if_present(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))

    ctx.on_cleanup(_cleanup_group)

    # No InferenceSpecification: a versioned model package can be registered against a
    # group with only metadata (filled in later via UpdateModelPackage), which avoids
    # CreateModelPackage's cross-account image-existence validation entirely while still
    # producing a real, non-empty group.
    # Tags are not supported on model package versions (only on the group).
    package_arn = sm.create_model_package(
        ModelPackageGroupName=group_name,
        ModelApprovalStatus="PendingManualApproval",
        ModelPackageDescription="sim2real behavioral probe placeholder version",
    )["ModelPackageArn"]

    def _cleanup_package() -> None:
        _delete_if_present(lambda: sm.delete_model_package(ModelPackageName=package_arn))

    ctx.on_cleanup(_cleanup_package)

    # Break exactly one thing: try to delete the group while it still owns a package.
    # (SageMaker reports this as ValidationException, not the ConflictException the
    # Smithy model lists as DeleteModelPackageGroup's only modeled error -- confirmed
    # against real AWS, not assumed from the model.)
    code, message = _error(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        f"Model Package Group {group_arn} cannot be deleted because it still contains "
        "Model Packages."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the group and its package must both still exist afterward.
    desc = sm.describe_model_package_group(ModelPackageGroupName=group_name)
    assert desc["ModelPackageGroupName"] == group_name, desc
    pkg_desc = sm.describe_model_package(ModelPackageName=package_arn)
    assert pkg_desc["ModelPackageArn"] == package_arn, pkg_desc

    # Positive control: remove the package, then the exact same delete call succeeds.
    sm.delete_model_package(ModelPackageName=package_arn)
    sm.delete_model_package_group(ModelPackageGroupName=group_name)

    code, message = _error(lambda: sm.describe_model_package_group(ModelPackageGroupName=group_name))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = f"ModelPackageGroup {group_arn} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Deletes prove gone AND unusable: a second delete on the same dead id also fails.
    code, message = _error(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))
    assert code == "ValidationException", f"expected ValidationException on re-delete, got {code!r}"
    expected_message = f"ModelPackageGroup {group_arn} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises,
    because accepting a call AWS refuses is a failure, not a message mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_if_present(fn) -> None:
    """Teardown delete: returns once SageMaker reports the resource does not exist, retries the
    'still contains Model Packages' refusal while a package delete settles, and raises the rest."""
    deadline = time.monotonic() + 30
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            err = exc.response["Error"]
            message = err.get("Message", "")
            gone = err["Code"] == "ResourceNotFound" or (
                err["Code"] == "ValidationException" and "does not exist" in message
            )
            if gone:
                return
            if "still contains" not in message or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
