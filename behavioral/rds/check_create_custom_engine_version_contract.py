"""create-custom-engine-version-contract."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-custom-engine-version-contract"
GROUP = 'engine_versions'
SERVICES = ['rds']

ERR_INVALID_PARAMETER_VALUE = "InvalidParameterValue"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises -- an emulator
    accepting a request real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expected CreateCustomDBEngineVersion to reject this call, but it succeeded and "
        f"returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCustomDBEngineVersion with an unrecognized Engine value is rejected because the
    engine is not recognized, while a real custom engine family ("custom-sqlserver-se") passes
    engine validation and fails only for a different, later reason."""
    rds = ctx.client("rds")

    control_version = "15.00.4073.23." + ctx.unique_name("cev").replace("-", "")
    control_error = _client_error(
        lambda: rds.create_custom_db_engine_version(
            Engine="custom-sqlserver-se",
            EngineVersion=control_version,
        )
    )
    assert control_error.get("Code") != ERR_INVALID_PARAMETER_VALUE or (
        control_version not in control_error.get("Message", "")
        and "engine version" not in control_error.get("Message", "").lower()
    ), (
        "a real custom engine family (custom-sqlserver-se) with a properly formatted "
        f"EngineVersion was rejected as if the Engine/EngineVersion pair itself were invalid, "
        f"so the negative below cannot be attributed to the bogus Engine value: {control_error!r}"
    )

    bogus_engine = "not-a-real-custom-engine"
    bogus_version = ctx.unique_name("sim2real-behav-cev-")
    error = _client_error(
        lambda: rds.create_custom_db_engine_version(
            Engine=bogus_engine,
            EngineVersion=bogus_version,
        )
    )
    assert error.get("Code") == ERR_INVALID_PARAMETER_VALUE, f"unexpected error code: {error!r}"
    assert error.get("Message") == "Invalid DB engine", error

    try:
        versions = rds.describe_db_engine_versions(
            Engine=bogus_engine, EngineVersion=bogus_version
        ).get("DBEngineVersions", [])
    except ClientError as exc:
        assert exc.response.get("Error", {}).get("Code") == ERR_INVALID_PARAMETER_VALUE, (
            f"unexpected error confirming no CEV was created: {exc.response.get('Error')}"
        )
        message = exc.response.get("Error", {}).get("Message")
        assert message == f"Unrecognized engine name: {bogus_engine}", message
    else:
        assert versions == [], (
            f"a CEV record exists for the rejected bogus engine/version: {versions!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
