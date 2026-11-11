"""create-instance-with-parameter-group-of-another-engine-family-rejected."""

from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-instance-with-parameter-group-of-another-engine-family-rejected"
GROUP = "parameter_groups"
SERVICES = ["rds"]

_FOREIGN_FAMILY = "mysql8.0"
#: Smallest classes, in order of preference; the first orderable for the default version is used,
#: so the parameter group is the only defect in the request.
_CLASSES = ("db.t4g.micro", "db.t3.micro")
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]
#: The refusal of a postgres instance given a group of another family; {pg}, {foreign} and
#: {family} are the group's name, the group's family and the engine version's own family.
_FOREIGN_FAMILY_REFUSED = (
    "InvalidParameterCombination",
    "The parameter group {pg} with DBParameterGroupFamily {foreign} can't be used for this "
    "instance. Use a parameter group with DBParameterGroupFamily {family}.",
)
#: DescribeDBInstances for an identifier that names no instance.
_INSTANCE_NOT_FOUND = ("DBInstanceNotFound", "DBInstance {inst} not found.")


def _error_detail(fn):
    """The AWS error (code, message) raised by fn(); raises when the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"the call that must be refused succeeded instead: {result!r}")


def _retry_delete(fn, *, timeout_s=300, interval_s=2):
    """A delete tolerating only not-found; anything else is retried, raising at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code.endswith(("NotFound", "NotFoundFault")):
                return
            if time.monotonic() >= deadline:
                raise RuntimeError(f"resource was not deleted: {exc!r}") from exc
            time.sleep(interval_s)


def _delete_instance_if_created(rds, inst_id):
    """Teardown for an instance the refused call must never have created."""
    try:
        rds.delete_db_instance(
            DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "DBInstanceNotFound":
            return
        raise
    rds.get_waiter("db_instance_deleted").wait(
        DBInstanceIdentifier=inst_id, WaiterConfig={"Delay": 5, "MaxAttempts": 240}
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDBInstance for postgres naming a mysql8.0-family DB parameter group is refused.

    The refusal is InvalidParameterCombination naming both families, and no instance is created.
    """
    rds = ctx.client("rds")
    default = rds.describe_db_engine_versions(Engine="postgres", DefaultOnly=True)[
        "DBEngineVersions"
    ]
    assert default, "DescribeDBEngineVersions lists no default postgres version"
    version, family = default[0]["EngineVersion"], default[0]["DBParameterGroupFamily"]
    db_class = next(
        (
            cls
            for cls in _CLASSES
            if rds.describe_orderable_db_instance_options(
                Engine="postgres", EngineVersion=version, DBInstanceClass=cls
            )["OrderableDBInstanceOptions"]
        ),
        None,
    )
    assert db_class, f"none of {_CLASSES!r} is orderable for postgres {version}"

    pg_name = ctx.unique_name("sim2real-behav-pg-")
    ctx.on_cleanup(
        lambda: _retry_delete(lambda: rds.delete_db_parameter_group(DBParameterGroupName=pg_name))
    )
    rds.create_db_parameter_group(
        DBParameterGroupName=pg_name,
        DBParameterGroupFamily=_FOREIGN_FAMILY,
        Description="sim2real foreign-family parameter group",
        Tags=_MANAGED_TAGS,
    )

    sng = ctx.unique_name("sim2real-behav-sng-")
    ctx.on_cleanup(lambda: _retry_delete(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=sng)))
    rds.create_db_subnet_group(
        DBSubnetGroupName=sng,
        DBSubnetGroupDescription="sim2real foreign-family parameter group",
        SubnetIds=ctx.network().subnet_ids,
        Tags=_MANAGED_TAGS,
    )

    inst_id = ctx.unique_name("sim2real-behav-inst-")
    ctx.on_cleanup(lambda: _delete_instance_if_created(rds, inst_id))
    got = _error_detail(
        lambda: rds.create_db_instance(
            DBInstanceIdentifier=inst_id,
            Engine="postgres",
            EngineVersion=version,
            DBInstanceClass=db_class,
            AllocatedStorage=20,
            MasterUsername="sim2real",
            MasterUserPassword="S2r" + secrets.token_urlsafe(18),
            DBParameterGroupName=pg_name,
            DBSubnetGroupName=sng,
            BackupRetentionPeriod=0,
            PubliclyAccessible=False,
            Tags=_MANAGED_TAGS,
        )
    )
    want = (
        _FOREIGN_FAMILY_REFUSED[0],
        _FOREIGN_FAMILY_REFUSED[1].format(pg=pg_name, foreign=_FOREIGN_FAMILY, family=family),
    )
    assert got == want, f"CreateDBInstance refusal: expected {want!r}, got {got!r}"

    absent = _error_detail(lambda: rds.describe_db_instances(DBInstanceIdentifier=inst_id))
    want_absent = (_INSTANCE_NOT_FOUND[0], _INSTANCE_NOT_FOUND[1].format(inst=inst_id))
    assert absent == want_absent, (
        f"the refused CreateDBInstance must leave no instance; DescribeDBInstances gave {absent!r},"
        f" expected {want_absent!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
