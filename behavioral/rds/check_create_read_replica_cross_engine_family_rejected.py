"""create-read-replica-cross-engine-family-rejected."""
from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-read-replica-cross-engine-family-rejected"
GROUP = "overly-permissive"
SERVICES = ["rds"]

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real", "Value": "create-read-replica-cross-engine-family-rejected"},
]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDBInstanceReadReplica must reject a request whose OptionGroupName belongs to a
    different DB engine family than the source instance (a postgres option group applied to a
    mysql source), rather than silently creating an unrelated/broken replica."""
    rds = ctx.client("rds")

    # Discover the current default postgres major version rather than hardcoding one, so the
    # check keeps working as AWS retires old major versions.
    pg_versions = rds.describe_db_engine_versions(Engine="postgres", DefaultOnly=True)[
        "DBEngineVersions"
    ]
    if not pg_versions:
        pg_versions = rds.describe_db_engine_versions(Engine="postgres")["DBEngineVersions"]
    pg_major = pg_versions[0]["EngineVersion"].split(".")[0]

    mysql_id = ctx.unique_name("sim2real-rds-xengfam-src-")
    password = "S2r" + secrets.token_hex(10)
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=mysql_id,
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        AllocatedStorage=20,
        BackupRetentionPeriod=1,
        PubliclyAccessible=False,
        Tags=_TAGS,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _cleanup_delete_when_ready(ctx, mysql_id))

    _poll_until(
        lambda: _describe_instance(rds, mysql_id),
        lambda inst: inst is not None and inst["DBInstanceStatus"] == "available",
        timeout_s=1200,
        interval_s=20,
    )

    mysql_version = ".".join(_describe_instance(rds, mysql_id)["EngineVersion"].split(".")[:2])

    pg_option_group = ctx.unique_name("sim2real-rds-pgog-")
    rds.create_option_group(
        OptionGroupName=pg_option_group,
        EngineName="postgres",
        MajorEngineVersion=pg_major,
        OptionGroupDescription="sim2real cross-engine-family negative test",
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _safe_delete_option_group(ctx, pg_option_group))

    # Break exactly one thing: attach a postgres-family option group to a mysql read replica.
    replica_bad_id = ctx.unique_name("sim2real-rds-xengfam-bad-")
    # Registered before the attempt: if the target is over-permissive and creates it anyway,
    # this must not be a leaked resource just because the rejection we expect did not happen.
    ctx.on_cleanup(lambda: _cleanup_delete_when_ready(ctx, replica_bad_id))
    code, message = _error(
        lambda: rds.create_db_instance_read_replica(
            DBInstanceIdentifier=replica_bad_id,
            SourceDBInstanceIdentifier=mysql_id,
            DBInstanceClass="db.t3.micro",
            OptionGroupName=pg_option_group,
            Tags=_TAGS,
        )
    )
    assert code == "InvalidParameterCombination", f"expected InvalidParameterCombination, got {code!r}"
    expected = (
        f"The option group {pg_option_group} is for postgres {pg_major}, and your DB instance "
        f"is mysql {mysql_version}."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no such replica instance was created.
    assert _describe_instance(rds, replica_bad_id) is None, (
        "a read replica should not exist after a rejected cross-engine-family request"
    )

    # Positive control: the identical call, minus the mismatched option group, must succeed and
    # actually create a replica of the source instance.
    replica_good_id = ctx.unique_name("sim2real-rds-xengfam-good-")
    rds.create_db_instance_read_replica(
        DBInstanceIdentifier=replica_good_id,
        SourceDBInstanceIdentifier=mysql_id,
        DBInstanceClass="db.t3.micro",
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _cleanup_delete_when_ready(ctx, replica_good_id))
    good = _describe_instance(rds, replica_good_id)
    assert good is not None, f"expected read replica {replica_good_id!r} to exist, found none"
    assert good["ReadReplicaSourceDBInstanceIdentifier"] == mysql_id, (
        f"expected replica source {mysql_id!r}, got {good.get('ReadReplicaSourceDBInstanceIdentifier')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected the cross-engine-family read replica request to be rejected, but it "
        f"SUCCEEDED and returned {result!r}"
    )


def _describe_instance(rds, db_id):
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "DBInstanceNotFound":
            return None
        raise


def _poll_until(probe, predicate, *, timeout_s=900, interval_s=15):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last!r}")


def _cleanup_delete_when_ready(ctx, db_id, timeout_s=1200) -> None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    try:
        while time.monotonic() < deadline:
            inst = _describe_instance(rds, db_id)
            if inst is None:
                return
            if inst["DBInstanceStatus"] in ("available", "failed", "incompatible-parameters"):
                break
            time.sleep(20)
        rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFound":
            raise


def _safe_delete_option_group(ctx, name) -> None:
    rds = ctx.client("rds")
    try:
        rds.delete_option_group(OptionGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "OptionGroupNotFoundFault":
            raise


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
