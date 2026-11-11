"""delete-model-package-group-with-versions-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-model-package-group-with-versions-rejected"
GROUP = "data-plane"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteModelPackageGroup is rejected while the group still contains a model
    package version; the group and its version remain intact, and deleting the version
    first then the (now-empty) group succeeds -- the in-file positive control."""
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    group_name = ctx.unique_name("sim2real-sm-mpg-del-")
    sm.create_model_package_group(ModelPackageGroupName=group_name)

    # CreateModelPackage validates that InferenceSpecification.Containers[*].Image is
    # reachable in ECR unless SkipModelValidation="All" is passed -- MEASURED against
    # real SageMaker: a placeholder image with no such repository is refused with
    # ValidationException, so no ECR repository has to be minted for this check.
    image = f"{account_id}.dkr.ecr.{region}.amazonaws.com/sim2real-placeholder:latest"
    package_arn = sm.create_model_package(
        ModelPackageGroupName=group_name,
        InferenceSpecification={
            "Containers": [{"Image": image}],
            "SupportedContentTypes": ["text/csv"],
            "SupportedResponseMIMETypes": ["text/csv"],
        },
        SkipModelValidation="All",
    )["ModelPackageArn"]

    def _cleanup():
        import time

        from botocore.exceptions import ClientError

        # The group delete is refused with "still contains Model Packages" until the package
        # delete settles: retry that refusal every 2 s for up to 120 s, then raise.
        deadline = time.monotonic() + 120
        for delete in (
            lambda: sm.delete_model_package(ModelPackageName=package_arn),
            lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name),
        ):
            while True:
                try:
                    delete()
                    break
                except ClientError as exc:
                    error = exc.response["Error"]
                    message = error.get("Message", "")
                    if error["Code"] == "ValidationException" and "does not exist" in message:
                        break
                    if "still contains" not in message or time.monotonic() >= deadline:
                        raise
                time.sleep(2)

    ctx.on_cleanup(_cleanup)

    group_arn = f"arn:aws:sagemaker:{region}:{account_id}:model-package-group/{group_name}"
    code, message = _error_code_and_message(
        lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message!r}"
    expected_message = (
        f"Model Package Group {group_arn} cannot be deleted because it still contains "
        "Model Packages."
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Effect (b): the group and its version are both still present and describable.
    group_desc = sm.describe_model_package_group(ModelPackageGroupName=group_name)
    assert group_desc["ModelPackageGroupName"] == group_name, (
        f"expected group {group_name!r} to survive the rejected delete, got {group_desc!r}"
    )
    pkg_desc = sm.describe_model_package(ModelPackageName=package_arn)
    assert pkg_desc["ModelPackageArn"] == package_arn, (
        f"expected version {package_arn!r} to survive the rejected delete, got {pkg_desc!r}"
    )

    # Effect (c): positive control -- remove the version, then the (now-empty) group
    # deletes cleanly (no exception raised).
    sm.delete_model_package(ModelPackageName=package_arn)
    sm.delete_model_package_group(ModelPackageGroupName=group_name)

    # Effect (d): the group delete is not just unraised -- an independent read at the
    # destination confirms the group is actually gone.
    final_code, final_message = _error_code_and_message(
        lambda: sm.describe_model_package_group(ModelPackageGroupName=group_name)
    )
    assert final_code == "ValidationException", (
        f"expected ValidationException describing a deleted group, got {final_code!r}: "
        f"{final_message!r}"
    )
    expected_gone = f"ModelPackageGroup {group_arn} does not exist."
    assert final_message == expected_gone, f"expected {expected_gone!r}, got {final_message!r}"


# ===== helpers =====
def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it succeeded and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
