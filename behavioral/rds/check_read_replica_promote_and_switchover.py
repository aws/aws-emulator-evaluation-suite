"""read-replica-promote-and-switchover."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "read-replica-promote-and-switchover"
GROUP = "state-machine"
SERVICES = ["rds"]

_MASTER_PW = "Sim2RealBehav1"
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:check", "Value": CHECK},
]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A PostgreSQL read replica reaches replicating, SwitchoverReadReplica rejects it with
    InvalidParameterValue, and PromoteReadReplica severs replication."""
    rds = ctx.client("rds")
    subnet_group = _create_subnet_group(ctx)

    # Pin to an ESTABLISHED (one-major-version-back) engine version rather than the account-wide
    # DEFAULT (`DefaultOnly=True`): a newly promoted default major can provision slowly enough to
    # push the replica's create -> available wait past its bounded poll.
    engine_version = _pick_established_engine_version(rds, "postgres")

    primary_id = ctx.unique_name("sim2real-behav-pri-")
    rds.create_db_instance(
        DBInstanceIdentifier=primary_id,
        # PostgreSQL, not MySQL: its replicas need no primary-side binlog parameter-group setup.
        Engine="postgres",
        EngineVersion=engine_version,
        DBInstanceClass="db.t3.micro",
        MasterUsername="simadmin",
        MasterUserPassword=_MASTER_PW,
        AllocatedStorage=20,
        DBSubnetGroupName=subnet_group,
        BackupRetentionPeriod=1,
        PubliclyAccessible=False,
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_instance_and_wait(rds, primary_id))
    _wait_instance_status(ctx, primary_id, {"available"}, timeout_s=900.0, interval_s=6.0)

    replica_id = ctx.unique_name("sim2real-behav-rep-")
    rds.create_db_instance_read_replica(
        DBInstanceIdentifier=replica_id,
        SourceDBInstanceIdentifier=primary_id,
        DBInstanceClass="db.t3.micro",
        PubliclyAccessible=False,
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_instance_and_wait(rds, replica_id))
    # A read replica lingers in transitional statuses (e.g. "configuring-enhanced-monitoring")
    # longer than a primary does.
    replica = _wait_instance_status(ctx, replica_id, {"available"}, timeout_s=900.0, interval_s=6.0)
    assert replica["ReadReplicaSourceDBInstanceIdentifier"] == primary_id, (
        f"expected source {primary_id!r}, got {replica.get('ReadReplicaSourceDBInstanceIdentifier')!r}"
    )
    repl_status = next(s for s in replica["StatusInfos"] if s["StatusType"] == "read replication")
    assert repl_status["Status"] == "replicating", f"expected replicating, got {repl_status!r}"

    # Negative: SwitchoverReadReplica does not support a plain same-Region RDS for PostgreSQL
    # read replica (as created above); real AWS rejects it as a parameter validation error that
    # names the replica and the engine, rather than an instance-state fault.
    code, message = _error(lambda: rds.switchover_read_replica(DBInstanceIdentifier=replica_id))
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    expected = (
        f"You can't switch over the DB instance {replica_id} because the operation is not "
        "supported for postgres engine."
    )
    assert message == expected, f"unexpected error message: {message!r} != {expected!r}"

    rds.promote_read_replica(DBInstanceIdentifier=replica_id)
    promoted = _wait_promoted(ctx, replica_id, timeout_s=300.0, interval_s=6.0)
    assert not promoted.get("ReadReplicaSourceDBInstanceIdentifier"), "replication should be severed after promotion"
    assert promoted["DBInstanceStatus"] == "available", f"expected available, got {promoted['DBInstanceStatus']!r}"


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises directly."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _pick_established_engine_version(rds, engine: str) -> str:
    """Return the latest MINOR version of the SECOND-newest major version for ``engine``."""
    versions = [
        v for v in rds.describe_db_engine_versions(Engine=engine)["DBEngineVersions"]
        if v.get("Status", "available") == "available"
    ]

    def _major(v: str) -> int:
        return int(v.split(".")[0])

    def _ver_key(v: str):
        return tuple(int(p) if p.isdigit() else p for p in v.split("."))

    majors = sorted({_major(v["EngineVersion"]) for v in versions}, reverse=True)
    target_major = majors[1] if len(majors) > 1 else majors[0]
    candidates = [v["EngineVersion"] for v in versions if _major(v["EngineVersion"]) == target_major]
    assert candidates, f"no {engine} engine versions found for major version {target_major}"
    return sorted(candidates, key=_ver_key)[-1]


def _poll_until(probe, predicate, *, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")



def _default_subnet_ids(ctx, count: int = 3) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    ids = sorted({s["SubnetId"] for s in subnets})[:count]
    assert len(ids) >= 2, "need at least 2 subnets"
    return ids


def _create_subnet_group(ctx) -> str:
    rds = ctx.client("rds")
    ec2 = ctx.client("ec2")
    subnet_ids = _default_subnet_ids(ctx)

    # Reuse a Complete group covering >=2 subnets in the same VPC: the per-account DB subnet group
    # quota is low, and creating one per run can hit DBSubnetGroupQuotaExceeded.
    vpc_id = ec2.describe_subnets(SubnetIds=subnet_ids)["Subnets"][0]["VpcId"]
    existing = rds.describe_db_subnet_groups()["DBSubnetGroups"]
    for g in existing:
        if g.get("VpcId") == vpc_id and g.get("SubnetGroupStatus") == "Complete" and len(g.get("Subnets", [])) >= 2:
            return g["DBSubnetGroupName"]

    name = ctx.unique_name("sim2real-behav-subnetgrp-")
    try:
        rds.create_db_subnet_group(
            DBSubnetGroupName=name,
            DBSubnetGroupDescription="sim2real behavioral check",
            SubnetIds=subnet_ids,
            Tags=_MANAGED_TAGS,
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "DBSubnetGroupQuotaExceeded":
            raise
        # Quota exhausted and nothing reusable: remove a stale group with this check's name prefix,
        # then retry the create once.
        for g in existing:
            gname = g["DBSubnetGroupName"]
            if not gname.startswith("sim2real-behav-subnetgrp-"):
                continue
            try:
                rds.delete_db_subnet_group(DBSubnetGroupName=gname)
            except ClientError:
                continue
            break
        else:
            raise
        rds.create_db_subnet_group(
            DBSubnetGroupName=name,
            DBSubnetGroupDescription="sim2real behavioral check",
            SubnetIds=subnet_ids,
            Tags=_MANAGED_TAGS,
        )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


def _wait_instance_status(ctx, instance_id: str, statuses: set[str], timeout_s: float = 420.0, interval_s: float = 10.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]

    return _poll_until(probe, lambda i: i["DBInstanceStatus"] in statuses, timeout_s=timeout_s, interval_s=interval_s)


def _wait_promoted(ctx, instance_id: str, timeout_s: float = 360.0, interval_s: float = 10.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]

    return _poll_until(
        probe,
        lambda i: i["DBInstanceStatus"] == "available" and not i.get("ReadReplicaSourceDBInstanceIdentifier"),
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


def _delete_instance_and_wait(rds, instance_id, timeout_s=1500.0):
    """Delete a DB instance and wait until it is gone: its subnet group cannot be deleted before."""
    try:
        rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("DBInstanceNotFound", "InvalidDBInstanceState"):
            raise
    rds.get_waiter("db_instance_deleted").wait(
        DBInstanceIdentifier=instance_id,
        WaiterConfig={"Delay": 2, "MaxAttempts": int(timeout_s // 2)},
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
