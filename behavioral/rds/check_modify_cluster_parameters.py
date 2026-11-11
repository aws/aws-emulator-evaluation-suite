"""modify-cluster-parameters."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "modify-cluster-parameters"
GROUP = 'cluster_parameter_groups'
SERVICES = ['rds']

def _default_param_family(rds, engine: str) -> str:
    """DBParameterGroupFamily of the current default version for *engine* (looked
    up dynamically so a rotated default family never drifts the check)."""
    resp = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True)
    versions = resp.get("DBEngineVersions", [])
    if not versions:
        versions = rds.describe_db_engine_versions(Engine=engine).get("DBEngineVersions", [])
    return versions[0]["DBParameterGroupFamily"]

def _find_cluster_parameter(rds, group_name: str, param_name: str):
    """Paginate DescribeDBClusterParameters via Marker until *param_name* is found."""
    marker = None
    while True:
        kwargs = {"DBClusterParameterGroupName": group_name}
        if marker:
            kwargs["Marker"] = marker
        resp = rds.describe_db_cluster_parameters(**kwargs)
        for p in resp.get("Parameters", []):
            if p.get("ParameterName") == param_name:
                return p
        marker = resp.get("Marker")
        if not marker:
            return None

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyDBClusterParameterGroup is reflected in DescribeDBClusterParameters."""
    rds = ctx.client("rds")
    pg_name = ctx.unique_name("sim2real-behav-cpg-")
    rds.create_db_cluster_parameter_group(
        DBClusterParameterGroupName=pg_name,
        DBParameterGroupFamily=_default_param_family(rds, "aurora-mysql"),
        Description="sim2real behavioral check",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_cluster_parameter_group(
        DBClusterParameterGroupName=pg_name))

    rds.modify_db_cluster_parameter_group(
        DBClusterParameterGroupName=pg_name,
        Parameters=[
            {"ParameterName": "max_connections", "ParameterValue": "90", "ApplyMethod": "immediate"}
        ],
    )

    param = _find_cluster_parameter(rds, pg_name, "max_connections")
    assert param is not None, "max_connections missing from cluster parameter group"
    assert param["ParameterValue"] == "90", (
        f"expected ParameterValue '90' after modify, got {param['ParameterValue']!r}"
    )
    assert param["Source"] == "user", (
        f"expected Source 'user' after an explicit ModifyDBClusterParameterGroup, "
        f"got {param['Source']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
