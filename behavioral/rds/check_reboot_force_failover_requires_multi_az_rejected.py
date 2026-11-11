"""reboot-force-failover-requires-multi-az-rejected."""
from __future__ import annotations

import secrets
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reboot-force-failover-requires-multi-az-rejected"
GROUP = "server-side"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RebootDBInstance(ForceFailover=True) on a single-AZ instance is rejected and leaves it
    untouched, while a plain reboot of the same instance is accepted and completes."""
    rds = ctx.client("rds")
    instance_id = ctx.unique_name("sim2real-rds-ffneg-")
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
        MultiAZ=False,
        PubliclyAccessible=False,
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-rds-ffneg"},
        ],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(
            DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True
        )
    )

    before = _wait_for_instance_status(rds, instance_id, "available", timeout_s=1200)
    assert before["MultiAZ"] is False, f"expected a single-AZ instance, got MultiAZ={before['MultiAZ']!r}"

    code, message = _error(
        lambda: rds.reboot_db_instance(DBInstanceIdentifier=instance_id, ForceFailover=True)
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    expected = (
        "ForceFailover cannot be specified since the instance is not configured for either "
        "MultiAZ or High Availability"
    )
    assert message == expected, f"unexpected error message: {message!r} != {expected!r}"

    # Effect absent: the instance must still be untouched -- no reboot was actually kicked off.
    unaffected = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
    assert unaffected["DBInstanceStatus"] == "available", (
        f"rejected ForceFailover reboot still changed instance status to "
        f"{unaffected['DBInstanceStatus']!r}"
    )

    # Positive control: a plain reboot (no ForceFailover) on the same instance is accepted.
    rds.reboot_db_instance(DBInstanceIdentifier=instance_id)
    after = _wait_for_instance_status(rds, instance_id, "available", timeout_s=900)
    assert after["DBInstanceStatus"] == "available", (
        f"expected the positive-control plain reboot to complete, got status "
        f"{after['DBInstanceStatus']!r}"
    )


def _rds_password() -> str:
    return "S2r" + secrets.token_hex(8)


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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
