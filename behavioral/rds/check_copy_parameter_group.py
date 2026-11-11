"""copy-parameter-group."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-parameter-group"
GROUP = 'parameter_groups'
SERVICES = ['rds']

ERR_DB_PARAMETER_GROUP_NOT_FOUND = "DBParameterGroupNotFound"

def _default_param_family(rds, engine: str) -> str:
    """DBParameterGroupFamily of the current default version for *engine*."""
    resp = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True)
    versions = resp.get("DBEngineVersions", [])
    if not versions:
        versions = rds.describe_db_engine_versions(Engine=engine).get("DBEngineVersions", [])
    return versions[0]["DBParameterGroupFamily"]

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CopyDBParameterGroup: copying a real parameter group produces an
    independently describable target group. Error boundary: an unknown source
    group rejects with DBParameterGroupNotFound."""
    rds = ctx.client("rds")
    src_name = ctx.unique_name("sim2real-behav-pg-src-")
    rds.create_db_parameter_group(
        DBParameterGroupName=src_name,
        DBParameterGroupFamily=_default_param_family(rds, "mysql"),
        Description="sim2real behavioral check source",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=src_name))

    bogus_src = ctx.unique_name("sim2real-behav-pg-missing-")
    code = message = None
    try:
        rds.copy_db_parameter_group(
            SourceDBParameterGroupIdentifier=bogus_src,
            TargetDBParameterGroupIdentifier=ctx.unique_name("sim2real-behav-pg-tgt-"),
            TargetDBParameterGroupDescription="should fail",
        )
    except ClientError as _e:
        code = _e.response.get("Error", {}).get("Code")
        message = _e.response.get("Error", {}).get("Message")
    assert code == ERR_DB_PARAMETER_GROUP_NOT_FOUND, f"unexpected error code: {code!r}"
    assert message == "Parameter group does not exist", message

    tgt_name = ctx.unique_name("sim2real-behav-pg-tgt-")
    rds.copy_db_parameter_group(
        SourceDBParameterGroupIdentifier=src_name,
        TargetDBParameterGroupIdentifier=tgt_name,
        TargetDBParameterGroupDescription="sim2real behavioral check target",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=tgt_name))
    resp = rds.describe_db_parameter_groups(DBParameterGroupName=tgt_name)
    found = resp["DBParameterGroups"][0]["DBParameterGroupName"]
    assert found == tgt_name, f"expected copied target {tgt_name!r} to be independently describable, got {found!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
