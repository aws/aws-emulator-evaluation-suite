"""delete-custom-engine-version-boundary."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-custom-engine-version-boundary"
GROUP = 'engine_versions'
SERVICES = ['rds']

ERR_ACCESS_DENIED = "AccessDenied"


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCustomDBEngineVersion for an unknown custom-oracle-ee version is rejected with
    AccessDenied and its exact message, and DescribeDBEngineVersions finds no engine version under
    that identity."""
    rds = ctx.client("rds")

    # Positive control: general RDS read access in this account is not broadly broken --
    # only the CEV-management surface is gated.
    rds.describe_db_engine_versions(Engine="mysql", MaxRecords=20)

    missing_version = ctx.unique_name("sim2real-behav-cev-missing-")
    error = _error(
        lambda: rds.delete_custom_db_engine_version(
            Engine="custom-oracle-ee",
            EngineVersion=missing_version,
        )
    )
    assert error.get("Code") == ERR_ACCESS_DENIED, f"unexpected error code: {error!r}"
    assert error.get("Message") == (
        "The custom engine version you requested may not exist or you don't have the required "
        "permission."
    ), f"AccessDenied message did not match the known entitlement-gate phrasing: {error!r}"

    # Effect absent: nothing was created under the attempted identity either.
    try:
        versions = rds.describe_db_engine_versions(
            Engine="custom-oracle-ee", EngineVersion=missing_version, IncludeAll=True
        ).get("DBEngineVersions", [])
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "InvalidParameterValue", (
            f"unexpected error confirming no CEV exists under {missing_version!r}: "
            f"{exc.response['Error']}"
        )
        assert exc.response["Error"].get("Message") == "Unrecognized engine name: custom-oracle-ee", (
            f"unexpected message confirming no CEV exists under {missing_version!r}: "
            f"{exc.response['Error']}"
        )
    else:
        assert versions == [], (
            f"a CEV exists under an identity nothing created: {versions!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
