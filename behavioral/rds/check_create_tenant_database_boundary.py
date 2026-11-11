"""create-tenant-database-boundary."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-tenant-database-boundary"
GROUP = 'tenant_databases'
SERVICES = ['rds']

ERR_DB_INSTANCE_NOT_FOUND = "DBInstanceNotFound"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTenantDatabase on a nonexistent DB instance is rejected with DBInstanceNotFound."""
    rds = ctx.client("rds")
    bogus_id = ctx.unique_name("sim2real-behav-dbi-missing-")
    code, message = _error_code(
        lambda: rds.create_tenant_database(
            DBInstanceIdentifier=bogus_id,
            MasterUsername="admin",
            TenantDBName="tenant1",
            MasterUserPassword="Sim2Real#Pass99",
        )
    )
    assert code == ERR_DB_INSTANCE_NOT_FOUND, (
        f"expected {ERR_DB_INSTANCE_NOT_FOUND!r}, got {code!r}"
    )
    assert message == f"DBInstance not found: {bogus_id}", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
