"""custom-engine-version-manifest-round-trip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "custom-engine-version-manifest-round-trip"
GROUP = "representation"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCustomDBEngineVersion with Engine="custom-oracle-ee" is rejected with InvalidParameterValue
    ("Invalid DB engine") and leaves no engine version behind, while the same call for
    "custom-sqlserver-ee" gets the AMI-specific Ec2ImagePropertiesNotSupportedFault."""
    rds = ctx.client("rds")

    rejected_engine = "custom-oracle-ee"
    version_name = "19." + ctx.unique_name("sim2real-cev-").strip("-")

    code, message = _error_code_and_message(
        lambda: rds.create_custom_db_engine_version(
            Engine=rejected_engine,
            EngineVersion=version_name,
            UseAwsProvidedLatestImage=True,
            ImageId="ami-0000000000sim2real",
            Description="sim2real CEV mutually-exclusive-image-source negative test",
        )
    )
    assert code == "InvalidParameterValue", (
        f"expected InvalidParameterValue for Engine={rejected_engine!r}, got {code!r}: {message!r}"
    )
    assert message == "Invalid DB engine", (
        f"expected the InvalidParameterValue to be about the Engine value itself, "
        f"got message {message!r}"
    )

    # Effect absent: the rejected request must not have left behind any CEV record under the
    # EngineVersion name it would have created. describe_db_engine_versions may itself reject
    # the "custom-oracle-ee" engine name with InvalidParameterValue in accounts/regions where
    # RDS Custom for Oracle has never been provisioned (no base CEV exists yet) -- that also
    # proves no CEV record was created, so treat it the same as an empty result.
    try:
        versions = rds.describe_db_engine_versions(
            Engine=rejected_engine, EngineVersion=version_name, IncludeAll=True
        ).get("DBEngineVersions", [])
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "InvalidParameterValue", (
            f"unexpected error describing engine versions for {rejected_engine}/{version_name!r}: "
            f"{exc.response['Error']}"
        )
        assert exc.response["Error"].get("Message") == f"Unrecognized engine name: {rejected_engine}", (
            f"unexpected message describing engine versions for {rejected_engine}/{version_name!r}: "
            f"{exc.response['Error']}"
        )
        versions = []
    assert versions == [], (
        f"a CEV record for {rejected_engine}/{version_name!r} exists after the create was "
        f"rejected: {versions!r}"
    )

    # Positive control: the identical call shape (same fake ImageId, same conflicting-field
    # combination) against a *recognized* custom engine reaches a different, field-specific
    # rejection -- proving CreateCustomDBEngineVersion is not blanket-denied in this account and
    # that "Invalid DB engine" above is specific to custom-oracle-ee, not universal.
    control_engine = "custom-sqlserver-ee"
    control_version_name = "15.00.4073.23." + ctx.unique_name("sim2realcev").strip("-")

    control_code, control_message = _error_code_and_message(
        lambda: rds.create_custom_db_engine_version(
            Engine=control_engine,
            EngineVersion=control_version_name,
            UseAwsProvidedLatestImage=True,
            ImageId="ami-0000000000sim2real",
            Description="sim2real CEV positive control -- recognized engine, same fake image",
        )
    )
    assert control_code == "Ec2ImagePropertiesNotSupportedFault", (
        f"expected the recognized engine {control_engine!r} to reach AMI validation instead of "
        f"an engine-recognition rejection, got {control_code!r}: {control_message!r}"
    )
    expected_control_message = (
        f"Image ami-0000000000sim2real doesn't exist in your account {ctx.account}. "
        f"Verify {ctx.account} is the owner of the EC2 image."
    )
    assert control_message == expected_control_message, (
        f"expected the control's rejection to name the fake AMI, got {control_message!r}"
    )

    # Effect absent for the control too: still no CEV record under its EngineVersion.
    control_versions = rds.describe_db_engine_versions(
        Engine=control_engine, EngineVersion=control_version_name, IncludeAll=True
    ).get("DBEngineVersions", [])
    assert control_versions == [], (
        f"a CEV record for {control_engine}/{control_version_name!r} exists after the "
        f"positive-control create was rejected: {control_versions!r}"
    )


def _error_code_and_message(fn) -> tuple[str, str | None]:
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
