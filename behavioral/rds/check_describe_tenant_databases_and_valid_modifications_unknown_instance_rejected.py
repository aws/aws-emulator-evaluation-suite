"""describe-tenant-databases-and-valid-modifications-unknown-instance-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-tenant-databases-and-valid-modifications-unknown-instance-rejected"
GROUP = "db_instances"
SERVICES = ["rds"]

ERR_DB_INSTANCE_NOT_FOUND = "DBInstanceNotFound"


def _error_code(fn):
    """The (code, message) ``fn`` raises; an unexpected success raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeTenantDatabases and DescribeValidDBInstanceModifications each reject a DB
    instance identifier that was never created, with DBInstanceNotFound."""
    rds = ctx.client("rds")
    bogus_id = ctx.unique_name("sim2real-behav-dbi-missing-")

    tenant_code, tenant_message = _error_code(
        lambda: rds.describe_tenant_databases(DBInstanceIdentifier=bogus_id)
    )
    assert tenant_code == ERR_DB_INSTANCE_NOT_FOUND, f"unexpected error code: {tenant_code!r}"
    expected = f"DBInstance {bogus_id} not found."
    assert tenant_message == expected, f"unexpected message: {tenant_message!r} (expected {expected!r})"

    valid_mod_code, valid_mod_message = _error_code(
        lambda: rds.describe_valid_db_instance_modifications(DBInstanceIdentifier=bogus_id)
    )
    assert valid_mod_code == ERR_DB_INSTANCE_NOT_FOUND, f"unexpected error code: {valid_mod_code!r}"
    expected_valid_mod = f"DBInstance not found: {bogus_id}"
    assert valid_mod_message == expected_valid_mod, (
        f"unexpected message: {valid_mod_message!r} (expected {expected_valid_mod!r})"
    )

    # Positive control: an unrelated, supported create call succeeds, so the rejections above
    # are about the unknown identifier and not a broken credential or region.
    pg_name = ctx.unique_name("sim2real-behav-pg-")
    rds.create_db_parameter_group(
        DBParameterGroupName=pg_name,
        DBParameterGroupFamily="mysql8.0",
        Description="sim2real positive control",
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=pg_name))
    created = rds.describe_db_parameter_groups(DBParameterGroupName=pg_name)["DBParameterGroups"]
    assert len(created) == 1 and created[0]["DBParameterGroupName"] == pg_name, (
        f"expected exactly one parameter group named {pg_name!r}, got {created!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
