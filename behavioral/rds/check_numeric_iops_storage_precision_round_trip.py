"""numeric-iops-storage-precision-round-trip."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "numeric-iops-storage-precision-round-trip"
GROUP = "representation"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AllocatedStorage, Iops, and StorageThroughput integers supplied to CreateDBInstance for
    gp3 storage come back byte-for-byte identical (no rounding, truncation, or unit
    conversion) on DescribeDBInstances."""
    rds = ctx.client("rds")
    instance_id = ctx.unique_name("sim2real-gp3num-")
    password = _rand_password()

    # 400 GiB is the smallest gp3 tier where custom IOPS/throughput become configurable for
    # MySQL. Its *baseline* (what you get by NOT specifying Iops/StorageThroughput) is
    # 12,000/500 — picking that exact pair would make this check pass against a target that
    # silently ignores the two parameters and just applies the tier baseline. Pinning values
    # above the baseline (14000/600) means the round-trip is only honest if the target actually
    # carried the requested numbers through, not merely landed on the tier's default.
    allocated_storage = 400
    iops = 14000
    storage_throughput = 600

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        Engine="mysql",
        DBInstanceClass="db.m5.large",
        AllocatedStorage=allocated_storage,
        StorageType="gp3",
        Iops=iops,
        StorageThroughput=storage_throughput,
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    )
    instance = _wait_instance_status(ctx, instance_id, "available", timeout_s=1800)

    assert instance["AllocatedStorage"] == allocated_storage, (
        f"AllocatedStorage mismatch: expected {allocated_storage}, got {instance['AllocatedStorage']!r}"
    )
    assert instance["Iops"] == iops, f"Iops mismatch: expected {iops}, got {instance['Iops']!r}"
    assert instance["StorageThroughput"] == storage_throughput, (
        f"StorageThroughput mismatch: expected {storage_throughput}, "
        f"got {instance['StorageThroughput']!r}"
    )


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _wait_instance_status(ctx, instance_id, target_status, timeout_s=1800, poll_s=20) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        if last["DBInstanceStatus"] == target_status and not last.get("PendingModifiedValues"):
            return last
        time.sleep(poll_s)
    raise AssertionError(
        f"instance {instance_id} never reached {target_status!r}, "
        f"last status {last and last['DBInstanceStatus']!r}"
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
