"""multi-az-standby-auto-failover-on-primary-failure."""
from __future__ import annotations

import secrets
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "multi-az-standby-auto-failover-on-primary-failure"
GROUP = "server-side"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RebootDBInstance(ForceFailover=True) on a Multi-AZ instance makes the service promote the
    standby: the primary and secondary Availability Zones swap, not merely the reboot completing."""
    rds = ctx.client("rds")
    instance_id = ctx.unique_name("sim2real-rds-maz-")
    password = _rds_password()
    subnet_group = _network_db_subnet_group(ctx, rds)

    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="s2rtest",
        MasterUserPassword=password,
        AllocatedStorage=20,
        StorageType="gp2",
        MultiAZ=True,
        PubliclyAccessible=False,
        DBSubnetGroupName=subnet_group,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(
            DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True
        )
    )

    before = _wait_for_instance_status(rds, instance_id, "available", timeout_s=1500)
    assert before["MultiAZ"] is True, f"instance not provisioned Multi-AZ: MultiAZ={before['MultiAZ']!r}"
    original_az = before["AvailabilityZone"]

    # SecondaryAvailabilityZone can appear a little after DBInstanceStatus=="available";
    # poll for it rather than treating one absent read as definitive.
    before = _poll_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0],
        lambda inst: bool(inst.get("SecondaryAvailabilityZone")),
        timeout_s=1200,
        interval_s=15,
    )
    original_secondary_az = before.get("SecondaryAvailabilityZone")
    assert original_secondary_az, "Multi-AZ instance has no SecondaryAvailabilityZone"

    rds.reboot_db_instance(DBInstanceIdentifier=instance_id, ForceFailover=True)

    # "available" can be reported briefly before the AZ swap shows in DescribeDBInstances,
    # so poll on the swap itself with a generous bound.
    after = _poll_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0],
        lambda inst: (
            inst["DBInstanceStatus"] == "available"
            and inst.get("AvailabilityZone") == original_secondary_az
        ),
        timeout_s=1500,
        interval_s=15,
    )

    # The service -- not us -- decided to promote the standby: the primary/standby AZs swap.
    assert after["AvailabilityZone"] == original_secondary_az, (
        f"primary AZ did not swap to the former standby AZ: "
        f"before={original_az!r} standby={original_secondary_az!r} after={after['AvailabilityZone']!r}"
    )
    assert after["SecondaryAvailabilityZone"] == original_az, (
        f"standby AZ did not become the former primary AZ: after={after['SecondaryAvailabilityZone']!r}"
    )



def _network_db_subnet_group(ctx: Any, rds: Any) -> str:
    """A DB subnet group over the run's shared network, deleted once the instance releases it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_subnet_group(rds, name))
    return name


def _delete_subnet_group(rds: Any, name: str, *, timeout_s: float = 1200.0) -> None:
    """Delete the subnet group, retrying while a deleting instance still holds it; any other
    error, or the deadline, raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rds.delete_db_subnet_group(DBSubnetGroupName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "DBSubnetGroupNotFoundFault":
                return
            if code != "InvalidDBSubnetGroupStateFault" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _rds_password() -> str:
    return "S2r" + secrets.token_hex(8)


def _wait_for_instance_status(rds: Any, instance_id: str, status: str, *, timeout_s: float) -> dict:
    def _probe() -> dict:
        return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]

    result = _poll_until(
        _probe, lambda inst: inst["DBInstanceStatus"] == status, timeout_s=timeout_s, interval_s=15
    )
    if result["DBInstanceStatus"] != status:
        raise AssertionError(
            f"instance {instance_id} never reached status {status!r} "
            f"(last: {result['DBInstanceStatus']!r})"
        )
    return result


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            return value
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
