"""e2e-read-replica-topology-consistency-flow."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-read-replica-topology-consistency-flow"
GROUP = "e2e"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A duplicate CreateDBInstance fails with DBInstanceAlreadyExists "DB instance already exists" and leaves
    the source unchanged; a read replica names the source and the source lists the replica, and deleting
    the replica removes it from the source's ReadReplicaDBInstanceIdentifiers."""
    rds = ctx.client("rds")
    source_id = ctx.unique_name("sim2real-replsrc-")
    replica_id = ctx.unique_name("sim2real-repl-")
    password = _rand_password()

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=source_id,
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        BackupRetentionPeriod=1,  # automated backups must be enabled to support read replicas
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=source_id, SkipFinalSnapshot=True)
    )
    source = _wait_instance_status(ctx, source_id, "available", timeout_s=1200)
    assert source.get("ReadReplicaDBInstanceIdentifiers", []) == [], (
        f"expected no read replicas on a freshly created source, got "
        f"{source.get('ReadReplicaDBInstanceIdentifiers')!r}"
    )
    source_create_time = source["InstanceCreateTime"]

    # Overly-permissive boundary: a second CreateDBInstance reusing the source's identifier must
    # be rejected server-side, not silently accepted / not silently returning the existing instance.
    import botocore.exceptions

    try:
        rds.create_db_instance(
            DBInstanceIdentifier=source_id,
            Engine="postgres",
            DBInstanceClass="db.t3.micro",
            AllocatedStorage=20,
            MasterUsername="s2radmin",
            MasterUserPassword=_rand_password(),
            PubliclyAccessible=False,
            DBSubnetGroupName=subnet_group,
        )
        raise AssertionError("duplicate CreateDBInstance with an in-use identifier was accepted")
    except botocore.exceptions.ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "DBInstanceAlreadyExists", f"unexpected error code {code!r}"
        message = exc.response["Error"].get("Message")
        assert message == "DB instance already exists", f"unexpected error message {message!r}"

    # Effect absent: the rejected duplicate did not replace or mutate the original source instance.
    unchanged = rds.describe_db_instances(DBInstanceIdentifier=source_id)["DBInstances"][0]
    assert unchanged["InstanceCreateTime"] == source_create_time, (
        f"source instance {source_id} InstanceCreateTime changed after a rejected duplicate "
        f"create ({unchanged['InstanceCreateTime']!r} != {source_create_time!r}); it may have "
        f"been replaced"
    )

    rds.create_db_instance_read_replica(
        DBInstanceIdentifier=replica_id,
        SourceDBInstanceIdentifier=source_id,
        DBInstanceClass="db.t3.micro",
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_instance_if_present(rds, replica_id))
    replica = _wait_instance_status(ctx, replica_id, "available", timeout_s=1200)
    assert replica["ReadReplicaSourceDBInstanceIdentifier"] == source_id, (
        f"replica {replica_id} ReadReplicaSourceDBInstanceIdentifier was "
        f"{replica.get('ReadReplicaSourceDBInstanceIdentifier')!r}, expected {source_id!r}"
    )

    source = _wait_source_replica_list(ctx, source_id, replica_id, want_present=True, timeout_s=180)
    assert replica_id in source["ReadReplicaDBInstanceIdentifiers"], (
        f"replica {replica_id} missing from source's ReadReplicaDBInstanceIdentifiers "
        f"{source['ReadReplicaDBInstanceIdentifiers']!r}"
    )

    rds.delete_db_instance(DBInstanceIdentifier=replica_id, SkipFinalSnapshot=True)
    rds.get_waiter("db_instance_deleted").wait(
        DBInstanceIdentifier=replica_id, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
    )

    source = _wait_source_replica_list(ctx, source_id, replica_id, want_present=False, timeout_s=180)
    assert replica_id not in source.get("ReadReplicaDBInstanceIdentifiers", []), (
        "source's read-replica list did not revert after the replica was deleted"
    )


def _delete_instance_if_present(rds, instance_id) -> None:
    """Teardown delete that tolerates an instance the check body already deleted."""
    try:
        rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    except rds.exceptions.DBInstanceNotFoundFault:
        pass


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _wait_instance_status(ctx, instance_id, target_status, timeout_s=1200, poll_s=20) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        if last["DBInstanceStatus"] == target_status:
            return last
        time.sleep(poll_s)
    raise AssertionError(
        f"instance {instance_id} never reached {target_status!r}, "
        f"last status {last and last['DBInstanceStatus']!r}"
    )


def _wait_source_replica_list(ctx, source_id, replica_id, want_present: bool, timeout_s=180, poll_s=10) -> dict:
    """Poll the source instance until its ReadReplicaDBInstanceIdentifiers either contains
    (want_present=True) or omits (want_present=False) the given replica id."""
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_instances(DBInstanceIdentifier=source_id)["DBInstances"][0]
        members = last.get("ReadReplicaDBInstanceIdentifiers", [])
        present = replica_id in members
        if present == want_present:
            return last
        time.sleep(poll_s)
    raise AssertionError(
        f"source {source_id} read-replica list never converged to want_present={want_present!r}; "
        f"last observed {last and last.get('ReadReplicaDBInstanceIdentifiers')!r}"
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
