"""create-model-package-duplicate-version-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-model-package-duplicate-version-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second unversioned CreateModelPackage reusing a name fails with ValidationException naming
    the existing package's ARN and only the original is listed, while a fresh name gets its own ARN
    that DescribeModelPackage returns."""
    sm = ctx.client("sagemaker")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    image = f"{account_id}.dkr.ecr.{ctx.region}.amazonaws.com/sim2real-nonexistent-repo:latest"

    def _inference_spec() -> dict:
        return {
            "Containers": [{"Image": image}],
            "SupportedContentTypes": ["text/csv"],
            "SupportedResponseMIMETypes": ["text/csv"],
            "SupportedRealtimeInferenceInstanceTypes": ["ml.m5.large"],
            "SupportedTransformInstanceTypes": ["ml.m5.large"],
        }

    package_name = ctx.unique_name("sim2real-mp-")

    # SkipModelValidation='All' is required here: CreateModelPackage validates ECR image
    # reachability, and this check's image
    # deliberately does not exist -- registration-only, nothing is pulled or run.
    first = sm.create_model_package(
        ModelPackageName=package_name,
        InferenceSpecification=_inference_spec(),
        SkipModelValidation="All",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    assert first["ModelPackageArn"], f"create_model_package({package_name!r}) returned no ARN: {first}"
    ctx.on_cleanup(lambda: sm.delete_model_package(ModelPackageName=package_name))

    # --- negative: reuse the exact same (unversioned) ModelPackageName ---
    code, message = _error_code_and_message(
        lambda: sm.create_model_package(
            ModelPackageName=package_name,
            InferenceSpecification=_inference_spec(),
            SkipModelValidation="All",
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message}"
    assert message == f"ModelPackage already exists: {first['ModelPackageArn']}", (
        f"expected the refusal to name the existing package's own ARN "
        f"({first['ModelPackageArn']!r}); got message={message!r}"
    )

    # effect absent: exactly one model package exists under that name, the original
    packages = sm.list_model_packages(NameContains=package_name)["ModelPackageSummaryList"]
    matching = [p for p in packages if p["ModelPackageName"] == package_name]
    assert len(matching) == 1, (
        f"expected exactly one ModelPackage named {package_name!r} after the "
        f"rejected duplicate create, found {len(matching)}"
    )
    assert matching[0]["ModelPackageArn"] == first["ModelPackageArn"], (
        f"expected the surviving package's ARN to be {first['ModelPackageArn']!r}, "
        f"got {matching[0]['ModelPackageArn']!r}"
    )

    # --- positive control: a different, unused ModelPackageName succeeds ---
    other_package_name = ctx.unique_name("sim2real-mp-other-")
    second = sm.create_model_package(
        ModelPackageName=other_package_name,
        InferenceSpecification=_inference_spec(),
        SkipModelValidation="All",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    assert second["ModelPackageArn"], f"create_model_package({other_package_name!r}) returned no ARN: {second}"
    assert second["ModelPackageArn"] != first["ModelPackageArn"], (
        f"positive control under a fresh name returned the ORIGINAL package's ARN: "
        f"{second['ModelPackageArn']!r}"
    )
    ctx.on_cleanup(lambda: sm.delete_model_package(ModelPackageName=other_package_name))

    # terminal read: independent of the create that produced `second`, through a
    # different operation.
    described_second = sm.describe_model_package(ModelPackageName=other_package_name)
    assert described_second["ModelPackageArn"] == second["ModelPackageArn"], (
        f"expected describe_model_package({other_package_name!r}) to report "
        f"{second['ModelPackageArn']!r}, got {described_second['ModelPackageArn']!r}"
    )


def _error_code_and_message(fn):
    """Call fn(); return its botocore (Error code, Error message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(
        f"expected the duplicate create to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
