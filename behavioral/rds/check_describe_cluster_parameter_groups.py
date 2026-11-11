"""describe-cluster-parameter-groups."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-cluster-parameter-groups"
GROUP = 'cluster_parameter_groups'
SERVICES = ['rds']


def _client_error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises AssertionError, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _default_param_family(rds, engine):
    resp = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True)
    versions = resp.get("DBEngineVersions", [])
    if not versions:
        versions = rds.describe_db_engine_versions(Engine=engine).get("DBEngineVersions", [])
    return versions[0]["DBParameterGroupFamily"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDBClusterParameterGroups: a real, freshly created cluster parameter group is
    describable by name and reports its declared family. Overly-permissive boundary: an unknown
    group name must be rejected with DBParameterGroupNotFound rather than returning an empty success.
    """
    rds = ctx.client("rds")
    family = _default_param_family(rds, "aurora-mysql")
    name = ctx.unique_name("sim2real-behav-cpg-")
    rds.create_db_cluster_parameter_group(
        DBClusterParameterGroupName=name,
        DBParameterGroupFamily=family,
        Description="behavioral check",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_cluster_parameter_group(DBClusterParameterGroupName=name))

    resp = rds.describe_db_cluster_parameter_groups(DBClusterParameterGroupName=name)
    groups = resp.get("DBClusterParameterGroups", [])
    assert len(groups) == 1
    assert groups[0]["DBParameterGroupFamily"] == family

    bogus_name = ctx.unique_name("sim2real-behav-cpg-missing-")
    code, message = _client_error(
        lambda: rds.describe_db_cluster_parameter_groups(DBClusterParameterGroupName=bogus_name)
    )
    assert code == "DBParameterGroupNotFound", f"unexpected error code: {code}"
    assert message == f"DBClusterParameterGroup not found: {bogus_name}", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
