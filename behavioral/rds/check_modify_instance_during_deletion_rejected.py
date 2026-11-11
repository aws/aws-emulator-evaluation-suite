"""modify-instance-during-deletion-rejected."""
from __future__ import annotations

import random
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-instance-during-deletion-rejected"
GROUP = "overly-permissive"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyDBInstance succeeds on an available instance, is rejected with InvalidDBInstanceState while
    the instance is deleting without applying the change, and is rejected with DBInstanceNotFound
    once the instance is gone."""
    rds = ctx.client("rds")
    instance_id = ctx.unique_name("sim2real-rds-mid-")
    password = _rds_password()

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="sim2real",
        MasterUserPassword=password,
        AllocatedStorage=20,
        BackupRetentionPeriod=0,
        MultiAZ=False,
        PubliclyAccessible=False,
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-rds-mid"},
        ],
        DBSubnetGroupName=subnet_group,
    )

    def _cleanup():
        try:
            rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DBInstanceNotFound":
                raise

    ctx.on_cleanup(_cleanup)

    _wait_for_instance_status(ctx, instance_id, {"available"}, timeout_s=900, interval_s=15)

    # --- positive control: ModifyDBInstance succeeds while the instance is available ---
    rds.modify_db_instance(
        DBInstanceIdentifier=instance_id, CopyTagsToSnapshot=True, ApplyImmediately=True
    )
    control_value = _poll_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0][
            "CopyTagsToSnapshot"
        ],
        lambda v: v is True,
        timeout_s=120,
        interval_s=5,
    )
    assert control_value is True, "positive-control ModifyDBInstance did not take effect"

    # --- break exactly one thing: start deletion, then modify mid-flight ---
    rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)

    code, message = _error(
        lambda: rds.modify_db_instance(
            DBInstanceIdentifier=instance_id, CopyTagsToSnapshot=False, ApplyImmediately=True
        ),
    )
    assert code == "InvalidDBInstanceState", f"expected InvalidDBInstanceState, got {code}"
    expected = "The specified database instance is currently in deleting state, which is a terminal state."
    assert message == expected, f"unexpected error message: {message!r} != {expected!r}"

    # effect absent: the attribute we tried to flip must still read True (unchanged)
    try:
        desc = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        assert desc["CopyTagsToSnapshot"] is True, "rejected ModifyDBInstance mutated the instance"
    except rds.exceptions.DBInstanceNotFoundFault:
        # deletion raced ahead of our describe call -- the instance is gone entirely, which is
        # also proof the modify never applied to a still-live resource.
        pass

    # --- the delete already in flight is left to finish: prove gone and unusable ---
    _wait_for_deleted(ctx, instance_id, timeout_s=1500, interval_s=15)

    delete_code, delete_message = _error(
        lambda: rds.modify_db_instance(
            DBInstanceIdentifier=instance_id, CopyTagsToSnapshot=True, ApplyImmediately=True
        ),
    )
    assert delete_code == "DBInstanceNotFound", f"expected DBInstanceNotFound, got {delete_code}"
    expected_gone = f"DB instance not found: {instance_id}"
    assert delete_message == expected_gone, (
        f"unexpected error message: {delete_message!r} != {expected_gone!r}"
    )


def _rds_password() -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=24)) + "9Aa"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _wait_for_deleted(ctx, instance_id, *, timeout_s=1500.0, interval_s=15.0):
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0][
                "DBInstanceStatus"
            ]
        except rds.exceptions.DBInstanceNotFoundFault:
            return
        time.sleep(interval_s)
    raise AssertionError(f"instance not deleted within {timeout_s}s (last status={last_status!r})")


def _wait_for_instance_status(ctx, instance_id, target_statuses, *, timeout_s=900.0, interval_s=15.0):
    rds = ctx.client("rds")

    def _probe():
        return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]

    inst = _poll_until(
        _probe, lambda i: i["DBInstanceStatus"] in target_statuses, timeout_s=timeout_s, interval_s=interval_s
    )
    return inst


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
