"""describe-engine-default-parameters."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-engine-default-parameters"
GROUP = 'parameter_groups'
SERVICES = ['rds']


def _rejection(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _default_param_family(rds, engine):
    resp = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True)
    versions = resp.get("DBEngineVersions", [])
    if not versions:
        versions = rds.describe_db_engine_versions(Engine=engine).get("DBEngineVersions", [])
    return versions[0]["DBParameterGroupFamily"]


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeEngineDefaultParameters for the 'postgres' family returns a non-empty parameter list, and
    a MaxRecords above the documented 20-100 range is rejected rather than clamped."""
    rds = ctx.client("rds")
    family = _default_param_family(rds, "postgres")

    resp = rds.describe_engine_default_parameters(DBParameterGroupFamily=family)
    defaults = resp["EngineDefaults"]
    assert defaults["DBParameterGroupFamily"] == family, (
        f"expected DBParameterGroupFamily={family!r}, got {defaults['DBParameterGroupFamily']!r}"
    )
    assert defaults.get("Parameters"), "expected non-empty engine-default parameters"

    err = _rejection(
        lambda: rds.describe_engine_default_parameters(
            DBParameterGroupFamily=family, MaxRecords=1000
        )
    )
    assert err.get("Code") == "InvalidParameterValue", (
        f"expected the service to reject MaxRecords=1000 with InvalidParameterValue, got: {err}"
    )
    assert err.get("Message") == "Invalid value 1000 for MaxRecords. Must be between 20 and 100", (
        f"unexpected InvalidParameterValue message: {err}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
