"""model-package-empty-vs-absent-fields-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "model-package-empty-vs-absent-fields-preserved"
GROUP = "representation"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An empty-string ModelPackageDescription is dropped: DescribeModelPackage and
    BatchDescribeModelPackage return no description for it, exactly as for an omitted one, and both
    summaries carry the same keys.
    """
    sm = ctx.client("sagemaker")
    group_name = ctx.unique_name("sim2real-mpg-")
    sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))

    # Tags are rejected on a versioned model package ("Please add them to the Model
    # Package Group") -- only the group above accepts Tags directly.
    empty_arn = sm.create_model_package(
        ModelPackageGroupName=group_name,
        ModelPackageDescription="",
    )["ModelPackageArn"]
    ctx.on_cleanup(lambda: sm.delete_model_package(ModelPackageName=empty_arn))

    absent_arn = sm.create_model_package(
        ModelPackageGroupName=group_name,
    )["ModelPackageArn"]
    ctx.on_cleanup(lambda: sm.delete_model_package(ModelPackageName=absent_arn))

    empty_direct = sm.describe_model_package(ModelPackageName=empty_arn)
    absent_direct = sm.describe_model_package(ModelPackageName=absent_arn)
    assert "ModelPackageDescription" not in empty_direct, (
        f"expected an explicit empty-string description to be normalized away (not stored) "
        f"for {empty_arn}, got {empty_direct.get('ModelPackageDescription')!r}"
    )
    assert "ModelPackageDescription" not in absent_direct, (
        f"expected an omitted description to stay absent for {absent_arn}, "
        f"got {absent_direct.get('ModelPackageDescription')!r}"
    )

    batch = sm.batch_describe_model_package(ModelPackageArnList=[empty_arn, absent_arn])
    summaries = batch["ModelPackageSummaries"]
    assert empty_arn in summaries and absent_arn in summaries, (
        f"expected both {empty_arn} and {absent_arn} in ModelPackageSummaries, got keys {list(summaries)}"
    )
    empty_summary = summaries[empty_arn]
    absent_summary = summaries[absent_arn]

    assert "ModelPackageDescription" not in empty_summary, (
        f"expected the empty-string description to be dropped from the summary for {empty_arn}, "
        f"got {empty_summary.get('ModelPackageDescription')!r}"
    )
    assert "ModelPackageDescription" not in absent_summary, (
        f"expected the omitted description to stay absent for {absent_arn}, "
        f"got {absent_summary.get('ModelPackageDescription')!r}"
    )

    per_instance_keys = {"ModelPackageVersion", "ModelPackageArn", "CreationTime"}
    empty_keys = set(empty_summary) - per_instance_keys
    absent_keys = set(absent_summary) - per_instance_keys
    assert empty_keys == absent_keys, (
        f"expected the empty-string and omitted packages to leave an identical summary shape "
        f"once per-instance fields are excluded, got {sorted(empty_keys)} vs {sorted(absent_keys)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
