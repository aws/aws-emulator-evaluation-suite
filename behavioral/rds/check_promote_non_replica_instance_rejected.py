"""promote-non-replica-instance-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "promote-non-replica-instance-rejected"
GROUP = "state-machine"
SERVICES = ["rds"]

_MASTER_PW = "Sim2RealBehav1"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PromoteReadReplica on a standalone (non-replica) DB instance is rejected."""
    rds = ctx.client("rds")
    subnet_group = _create_subnet_group(ctx)

    instance_id = ctx.unique_name("sim2real-behav-in-")
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        MasterUsername="simadmin",
        MasterUserPassword=_MASTER_PW,
        AllocatedStorage=20,
        DBSubnetGroupName=subnet_group,
        BackupRetentionPeriod=1,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_instance_and_wait(rds, instance_id))
    instance = _wait_instance_status(ctx, instance_id, {"available"}, timeout_s=1500.0)
    assert not instance.get("ReadReplicaSourceDBInstanceIdentifier"), (
        f"positive control: a freshly created standalone instance must have no replica source, "
        f"got {instance.get('ReadReplicaSourceDBInstanceIdentifier')!r}"
    )

    code, message = _error(lambda: rds.promote_read_replica(DBInstanceIdentifier=instance_id))
    assert code == "InvalidDBInstanceState", f"expected InvalidDBInstanceState, got {code!r}"
    expected = "DB Instance is not a read replica."
    assert message == expected, f"unexpected error message: {message!r} != {expected!r}"

    # The instance is untouched by the rejected promotion attempt.
    instance = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
    assert instance["DBInstanceStatus"] == "available", (
        f"expected status unchanged at 'available' after the rejected promotion, got {instance['DBInstanceStatus']!r}"
    )
    assert not instance.get("ReadReplicaSourceDBInstanceIdentifier"), (
        "the rejected PromoteReadReplica call must not have turned the instance into a replica of itself"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call unexpectedly succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _delete_instance_and_wait(rds, instance_id: str, timeout_s: float = 900.0) -> None:
    """Delete the instance and wait until it is gone, so the subnet group cleanup can run."""
    try:
        rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "DBInstanceNotFound":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_instances(DBInstanceIdentifier=instance_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "DBInstanceNotFound":
                return
            raise
        time.sleep(15)
    raise AssertionError(f"instance {instance_id} still present {timeout_s}s after DeleteDBInstance")


def _default_subnet_ids(ctx, count: int = 3) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    ids = sorted(by_az.values())[:count]
    assert len(ids) >= 2, "a DB subnet group needs subnets in at least 2 distinct availability zones"
    return ids


def _create_subnet_group(ctx) -> str:
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-subnetgrp-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check",
        SubnetIds=_default_subnet_ids(ctx),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


def _wait_instance_status(ctx, instance_id: str, statuses: set[str], timeout_s: float = 1500.0, interval_s: float = 20.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]

    return _poll_until(probe, lambda i: i["DBInstanceStatus"] in statuses, timeout_s=timeout_s, interval_s=interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
