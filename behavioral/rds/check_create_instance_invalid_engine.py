"""create-instance-invalid-engine."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
import secrets

CHECK = "create-instance-invalid-engine"
GROUP = 'errors'
SERVICES = ['rds']

ERR_INVALID_PARAMETER_VALUE = "InvalidParameterValue"
ERR_DB_INSTANCE_NOT_FOUND = "DBInstanceNotFound"
_USER = "sim2real"
_PASS = "Aa1!" + secrets.token_urlsafe(18)
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _instance(rds, inst_id):
    """DescribeDBInstances for one id, or None when it does not exist."""
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == ERR_DB_INSTANCE_NOT_FOUND:
            return None
        raise


def _delete_instance(rds, inst_id):
    """Best-effort teardown: delete an instance with no final snapshot."""
    try:
        rds.delete_db_instance(
            DBInstanceIdentifier=inst_id,
            SkipFinalSnapshot=True,
            DeleteAutomatedBackups=True,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFound":
            raise


def _poll(fn, pred, *, timeout_s, interval_s=10):
    """Poll fn() until pred(value) or the deadline; returns the last value seen."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDBInstance with a nonexistent engine is rejected with InvalidParameterValue, while
    the same request with a real engine is accepted and becomes describable."""
    rds = ctx.client("rds")
    subnet_group = _network_db_subnet_group(ctx, rds)

    # --- Positive control: the identical request shape with a real engine is accepted.
    good_id = ctx.unique_name("sim2real-behav-inst-goodengine-")
    ctx.on_cleanup(lambda: _delete_instance(rds, good_id))
    resp = rds.create_db_instance(
        DBInstanceIdentifier=good_id,
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername=_USER,
        MasterUserPassword=_PASS,
        BackupRetentionPeriod=0,
        DeletionProtection=False,
        Tags=_MANAGED_TAGS,
        DBSubnetGroupName=subnet_group,
    )
    assert resp["DBInstance"]["DBInstanceIdentifier"] == good_id, (
        f"positive control: expected {good_id!r} in the CreateDBInstance response, got "
        f"{resp['DBInstance'].get('DBInstanceIdentifier')!r}"
    )
    good_inst = _poll(
        lambda: _instance(rds, good_id), lambda i: i is not None, timeout_s=120, interval_s=5
    )
    assert good_inst is not None, (
        f"positive control: CreateDBInstance with Engine='mysql' was accepted but {good_id} "
        "never became describable -- the account/credentials are not healthy for "
        "CreateDBInstance, so the negative below would not be a meaningful assertion"
    )
    assert good_inst["Engine"] == "mysql", (
        f"positive control: expected the created instance to report Engine='mysql', got "
        f"{good_inst['Engine']!r}"
    )

    # --- Negative: a nonexistent engine value is rejected, and nothing is minted.
    bad_id = ctx.unique_name("sim2real-behav-inst-badengine-")
    try:
        rds.create_db_instance(
            DBInstanceIdentifier=bad_id,
            Engine="not-a-real-rds-engine",
            DBInstanceClass="db.t3.micro",
            AllocatedStorage=20,
            MasterUsername=_USER,
            MasterUserPassword=_PASS,
            DBSubnetGroupName=subnet_group,
        )
        code = message = None
    except ClientError as _e:
        code = _e.response.get("Error", {}).get("Code")
        message = _e.response.get("Error", {}).get("Message")
    assert code == ERR_INVALID_PARAMETER_VALUE, f"unexpected error code: {code!r}"
    assert message == "Invalid DB engine", message
    assert _instance(rds, bad_id) is None, (
        f"the refused CreateDBInstance still minted {bad_id}; a rejection must leave no "
        "resource behind"
    )


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
