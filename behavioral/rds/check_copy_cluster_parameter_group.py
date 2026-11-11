"""copy-cluster-parameter-group."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-cluster-parameter-group"
GROUP = 'cluster_parameter_groups'
SERVICES = ['rds']

ERR_DB_PARAMETER_GROUP_NOT_FOUND = "DBParameterGroupNotFound"

def _default_param_family(rds, engine: str) -> str:
    """DBParameterGroupFamily of the current default version for *engine*."""
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

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CopyDBClusterParameterGroup copies the source's family and customized parameter values
    into a describable target; an unknown source group rejects with DBParameterGroupNotFound."""
    rds = ctx.client("rds")
    src_name = ctx.unique_name("sim2real-behav-cpg-src-")
    src_family = _default_param_family(rds, "aurora-mysql")
    rds.create_db_cluster_parameter_group(
        DBClusterParameterGroupName=src_name,
        DBParameterGroupFamily=src_family,
        Description="sim2real behavioral check source",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_cluster_parameter_group(
        DBClusterParameterGroupName=src_name))

    rds.modify_db_cluster_parameter_group(
        DBClusterParameterGroupName=src_name,
        Parameters=[
            {"ParameterName": "max_connections", "ParameterValue": "90", "ApplyMethod": "immediate"}
        ],
    )
    src_param = _find_cluster_parameter(rds, src_name, "max_connections")
    assert src_param is not None, "max_connections missing from source cluster parameter group"
    assert src_param["ParameterValue"] == "90", (
        f"source max_connections not set before copy: {src_param.get('ParameterValue')!r}"
    )

    bogus_src = ctx.unique_name("sim2real-behav-cpg-missing-")
    code = message = None
    try:
        rds.copy_db_cluster_parameter_group(
            SourceDBClusterParameterGroupIdentifier=bogus_src,
            TargetDBClusterParameterGroupIdentifier=ctx.unique_name("sim2real-behav-cpg-tgt-"),
            TargetDBClusterParameterGroupDescription="should fail",
        )
    except ClientError as _e:
        code = _e.response.get("Error", {}).get("Code")
        message = _e.response.get("Error", {}).get("Message")
    assert code == ERR_DB_PARAMETER_GROUP_NOT_FOUND, f"unexpected error code: {code!r}"
    assert message == "Parameter group does not exist", message

    tgt_name = ctx.unique_name("sim2real-behav-cpg-tgt-")
    rds.copy_db_cluster_parameter_group(
        SourceDBClusterParameterGroupIdentifier=src_name,
        TargetDBClusterParameterGroupIdentifier=tgt_name,
        TargetDBClusterParameterGroupDescription="sim2real behavioral check target",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_cluster_parameter_group(
        DBClusterParameterGroupName=tgt_name))
    resp = rds.describe_db_cluster_parameter_groups(DBClusterParameterGroupName=tgt_name)
    group = resp["DBClusterParameterGroups"][0]
    assert group["DBClusterParameterGroupName"] == tgt_name
    assert group["DBParameterGroupFamily"] == src_family, (
        f"target family {group['DBParameterGroupFamily']!r} != source family {src_family!r}"
    )

    tgt_param = _find_cluster_parameter(rds, tgt_name, "max_connections")
    assert tgt_param is not None, "max_connections missing from copied target cluster parameter group"
    assert tgt_param["ParameterValue"] == "90", (
        f"copy did not carry the source's customized value: {tgt_param.get('ParameterValue')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
