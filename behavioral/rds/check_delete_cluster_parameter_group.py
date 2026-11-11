"""delete-cluster-parameter-group."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-cluster-parameter-group"
GROUP = 'cluster_parameter_groups'
SERVICES = ['rds']

ERR_DB_PARAMETER_GROUP_NOT_FOUND = "DBParameterGroupNotFound"


def _error_code(fn, *, expect):
    """Call fn(); return its botocore error code and message."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected {expect}, but the call SUCCEEDED: {result!r}")


def _default_param_family(ctx, engine: str) -> str:
    """DBParameterGroupFamily of the current default engine version for
    *engine* (e.g. "aurora-mysql"). Derived dynamically so the family never
    drifts as AWS rotates the default away."""
    rds = ctx.client("rds")
    resp = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True)
    versions = resp.get("DBEngineVersions", [])
    if not versions:
        versions = rds.describe_db_engine_versions(Engine=engine).get("DBEngineVersions", [])
    return versions[0]["DBParameterGroupFamily"]


def _delete_unless_gone(delete, gone_code):
    """Teardown delete; an already-deleted resource answers ``gone_code`` (documented not-found)."""
    try:
        delete()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != gone_code:
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDBClusterParameterGroup: a real cluster parameter group is
    deleted and stops being describable. Error boundary: deleting it again
    (now unknown) rejects with DBParameterGroupNotFound.
    """
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-cpg-")
    rds.create_db_cluster_parameter_group(
        DBClusterParameterGroupName=name,
        DBParameterGroupFamily=_default_param_family(ctx, "aurora-mysql"),
        Description="behavioral check",
        Tags=[{"Key": "sim2real-behavioral-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_unless_gone(
        lambda: rds.delete_db_cluster_parameter_group(DBClusterParameterGroupName=name),
        "DBParameterGroupNotFound"))

    rds.delete_db_cluster_parameter_group(DBClusterParameterGroupName=name)
    code, message = _error_code(
        lambda: rds.describe_db_cluster_parameter_groups(DBClusterParameterGroupName=name),
        expect=f"{ERR_DB_PARAMETER_GROUP_NOT_FOUND} describing the deleted group {name!r}",
    )
    assert code == ERR_DB_PARAMETER_GROUP_NOT_FOUND, (
        f"expected {ERR_DB_PARAMETER_GROUP_NOT_FOUND}, got {code!r}"
    )
    assert message == f"DBClusterParameterGroup not found: {name}", message

    code2, message2 = _error_code(
        lambda: rds.delete_db_cluster_parameter_group(DBClusterParameterGroupName=name),
        expect=f"{ERR_DB_PARAMETER_GROUP_NOT_FOUND} re-deleting the already-deleted group {name!r}",
    )
    assert code2 == ERR_DB_PARAMETER_GROUP_NOT_FOUND, (
        f"expected {ERR_DB_PARAMETER_GROUP_NOT_FOUND}, got {code2!r}"
    )
    assert message2 == f"DBClusterParameterGroup not found: {name}", message2


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
