"""copy-db-parameter-group-rejects-an-existing-target-name."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-db-parameter-group-rejects-an-existing-target-name"
GROUP = "parameter_groups"
SERVICES = ["rds"]


def _default_param_family(rds, engine: str) -> str:
    """The DBParameterGroupFamily of the current default version for *engine*."""
    versions = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True).get(
        "DBEngineVersions", []
    )
    return versions[0]["DBParameterGroupFamily"]


def _error(fn):
    """The ``Error`` dict ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CopyDBParameterGroup refuses to copy onto a target name that already names a parameter
    group, leaves that group untouched, and still succeeds against a fresh target name.
    """
    rds = ctx.client("rds")
    family = _default_param_family(rds, "mariadb")

    src = ctx.unique_name("sim2real-behav-pg-src-")
    rds.create_db_parameter_group(
        DBParameterGroupName=src,
        DBParameterGroupFamily=family,
        Description="sim2real behavioral copy-target-exists source",
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=src))

    taken = ctx.unique_name("sim2real-behav-pg-taken-")
    taken_description = "sim2real behavioral pre-existing target"
    rds.create_db_parameter_group(
        DBParameterGroupName=taken, DBParameterGroupFamily=family, Description=taken_description
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=taken))

    error = _error(
        lambda: rds.copy_db_parameter_group(
            SourceDBParameterGroupIdentifier=src,
            TargetDBParameterGroupIdentifier=taken,
            TargetDBParameterGroupDescription="should not land",
        )
    )
    assert error["Code"] == "DBParameterGroupAlreadyExists", (
        f"expected copying onto the existing name {taken!r} to be refused with "
        f"DBParameterGroupAlreadyExists, got {error['Code']!r}: {error.get('Message')!r}"
    )
    assert error["Message"] == f"Parameter group {taken} already exists", (
        f"expected the exact already-exists message naming {taken!r}, got {error['Message']!r}"
    )

    unchanged = rds.describe_db_parameter_groups(DBParameterGroupName=taken)["DBParameterGroups"][0]
    assert unchanged["Description"] == taken_description, (
        f"the rejected copy must not have touched the pre-existing group {taken!r}: expected "
        f"description {taken_description!r}, got {unchanged['Description']!r}"
    )

    fresh = ctx.unique_name("sim2real-behav-pg-fresh-")
    rds.copy_db_parameter_group(
        SourceDBParameterGroupIdentifier=src,
        TargetDBParameterGroupIdentifier=fresh,
        TargetDBParameterGroupDescription="sim2real behavioral copy-target-exists fresh target",
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=fresh))
    created = rds.describe_db_parameter_groups(DBParameterGroupName=fresh)["DBParameterGroups"][0]
    assert created["DBParameterGroupName"] == fresh, (
        f"expected the identical copy call to succeed against a fresh target name, got "
        f"{created['DBParameterGroupName']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
