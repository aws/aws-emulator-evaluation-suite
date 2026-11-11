"""model-package-unicode-description-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "model-package-unicode-description-round-trip"
GROUP = "representation"
SERVICES = ["sagemaker"]

_UNICODE_DESCRIPTION = "café naïve 日本語モデル ключевая модель português Ω→β 中文说明"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A multi-byte unicode ModelPackageDescription is preserved byte-for-byte via BatchDescribeModelPackage."""
    sm = ctx.client("sagemaker")
    group_name = ctx.unique_name("sim2real-mpg-")
    sm.create_model_package_group(ModelPackageGroupName=group_name)
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))

    pkg_arn = sm.create_model_package(
        ModelPackageGroupName=group_name,
        ModelPackageDescription=_UNICODE_DESCRIPTION,
    )["ModelPackageArn"]
    ctx.on_cleanup(lambda: sm.delete_model_package(ModelPackageName=pkg_arn))

    resp = sm.batch_describe_model_package(ModelPackageArnList=[pkg_arn])
    error_map = resp.get("BatchDescribeModelPackageErrorMap", {})
    assert pkg_arn not in error_map, f"expected {pkg_arn} to describe cleanly, got error {error_map.get(pkg_arn)}"
    summary = resp["ModelPackageSummaries"][pkg_arn]
    assert summary["ModelPackageDescription"] == _UNICODE_DESCRIPTION, (
        f"expected description {_UNICODE_DESCRIPTION!r}, got {summary['ModelPackageDescription']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
