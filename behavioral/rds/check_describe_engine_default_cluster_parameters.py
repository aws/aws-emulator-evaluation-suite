"""describe-engine-default-cluster-parameters."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-engine-default-cluster-parameters"
GROUP = 'cluster_parameter_groups'
SERVICES = ['rds']


def _rejection(fn):
    """Call fn() and return its botocore Error dict; raise if the call succeeds."""
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
    """DescribeEngineDefaultClusterParameters returns non-empty defaults for the aurora-postgresql
    family, and MaxRecords=5 (below 20-100) fails InvalidParameterValue instead of being clamped.
    """
    rds = ctx.client("rds")
    family = _default_param_family(rds, "aurora-postgresql")

    resp = rds.describe_engine_default_cluster_parameters(DBParameterGroupFamily=family)
    defaults = resp["EngineDefaults"]
    assert defaults["DBParameterGroupFamily"] == family, (
        f"expected family {family!r}, got {defaults['DBParameterGroupFamily']!r}"
    )
    assert defaults.get("Parameters"), "expected non-empty engine-default cluster parameters"

    err = _rejection(
        lambda: rds.describe_engine_default_cluster_parameters(
            DBParameterGroupFamily=family, MaxRecords=5
        )
    )
    assert err.get("Code") == "InvalidParameterValue", f"unexpected error: {err}"
    assert err.get("Message") == "Invalid value 5 for MaxRecords. Must be between 20 and 100", (
        f"unexpected InvalidParameterValue message: {err}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
