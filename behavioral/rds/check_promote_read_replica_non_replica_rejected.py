"""promote-read-replica-non-replica-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "promote-read-replica-non-replica-rejected"
GROUP = "state-machine"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PromoteReadReplica on a standalone (non-replica) DB instance is rejected and leaves it untouched."""
    rds = ctx.client("rds")

    sng = _subnet_group(ctx)
    inst_id = ctx.unique_name("sim2real-nonrepl-")
    rds.create_db_instance(
        DBInstanceIdentifier=inst_id,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="Sim2RealBehav1!",
        AllocatedStorage=20,
        DBSubnetGroupName=sng,
        BackupRetentionPeriod=1,
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, inst_id))

    _wait_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0],
        lambda i: i["DBInstanceStatus"] == "available",
        timeout_s=1800, interval_s=30, desc="instance available",
    )

    try:
        rds.promote_read_replica(DBInstanceIdentifier=inst_id)
        raise AssertionError("PromoteReadReplica on a standalone instance unexpectedly succeeded")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "InvalidDBInstanceState", f"expected InvalidDBInstanceState, got {code!r}"
        message = e.response["Error"].get("Message", "")
        expected = "DB Instance is not a read replica."
        assert message == expected, f"unexpected error message: {message!r} != {expected!r}"

    # Positive control: the instance was not mutated by the rejected call.
    unchanged = rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
    assert unchanged["DBInstanceStatus"] == "available", (
        f"expected status available after rejected promote, got {unchanged['DBInstanceStatus']!r}"
    )
    assert "ReadReplicaSourceDBInstanceIdentifier" not in unchanged, (
        "expected no ReadReplicaSourceDBInstanceIdentifier after rejected promote, "
        f"got {unchanged.get('ReadReplicaSourceDBInstanceIdentifier')!r}"
    )


def _wait_until(probe, predicate, timeout_s, interval_s=20, desc="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}; last={last}")
        time.sleep(interval_s)


def _wait_gone(probe, not_found_codes, timeout_s, interval_s=20, desc="deletion"):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            probe()
        except ClientError as e:
            if e.response["Error"]["Code"] in not_found_codes:
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}")
        time.sleep(interval_s)


def _subnet_group(ctx, name_prefix="sim2real-sng-"):

    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to build a DB subnet group")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < 2:
        raise AssertionError("shared network does not span enough AZs for a DB subnet group")
    name = ctx.unique_name(name_prefix)
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check subnet group",
        SubnetIds=subnet_ids[:3],
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


def _delete_instance(rds, inst_id):
    try:
        rds.delete_db_instance(DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "DBInstanceNotFound":
            raise
        return
    _wait_gone(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=inst_id),
        {"DBInstanceNotFound"}, timeout_s=1200, interval_s=20, desc=f"instance {inst_id} deleted",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
