"""reboot-db-instance-conflict-while-creating-then-succeeds."""
from __future__ import annotations

import secrets
import time

from behavioral_harness import tags

CHECK = "reboot-db-instance-conflict-while-creating-then-succeeds"
GROUP = "overly-permissive"
SERVICES = ["timestream-influxdb"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RebootDbInstance on a CREATING instance is refused with ValidationException and its
    exact message and starts no reboot; once the instance is AVAILABLE the same reboot
    succeeds and it returns to AVAILABLE."""
    net = _ensure_network(ctx)
    influx = ctx.client("timestream-influxdb")
    name = ctx.unique_name("sim2real-rebootconflict-")
    created = influx.create_db_instance(
        name=name,
        password=secrets.token_hex(12),
        dbInstanceType="db.influx.medium",
        vpcSubnetIds=net["subnet_ids"],
        vpcSecurityGroupIds=[net["security_group_id"]],
        allocatedStorage=20,
        dbStorageType="InfluxIOIncludedT1",
        deploymentType="SINGLE_AZ",
        tags={"sim2real": CHECK},
    )
    instance_id = created["id"]
    ctx.on_cleanup(lambda: _delete_instance_if_present(ctx, instance_id))

    # Break exactly one thing: reboot while still CREATING. AWS refuses this with
    # ValidationException, not ConflictException: the state conflict surfaces as a
    # request-validation failure.
    code, message = _error_detail(lambda: influx.reboot_db_instance(identifier=instance_id))
    assert code == "ValidationException", f"expected ValidationException, got {code!r} ({message!r})"
    account_id = created["arn"].split(":")[4]
    assert message == (
        f"DbInstance with identifier {instance_id} and customer id {account_id} is not in a rebootable state"
    ), message
    # The refused reboot starts nothing: the instance is still provisioning or has since
    # finished it, never REBOOTING.
    mid_state = influx.get_db_instance(identifier=instance_id)
    assert mid_state["status"] in ("CREATING", "AVAILABLE"), (
        f"rejected reboot must not alter instance state, got {mid_state['status']!r}"
    )

    available = _poll_until(
        lambda: influx.get_db_instance(identifier=instance_id),
        lambda r: r["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=2400,
        interval_s=30,
    )
    assert available["status"] == "AVAILABLE", f"expected AVAILABLE, got {available['status']!r}"

    # The identical reboot succeeds once the instance is AVAILABLE.
    influx.reboot_db_instance(identifier=instance_id)
    rebooted = _poll_until(
        lambda: influx.get_db_instance(identifier=instance_id),
        lambda r: r["status"] == "AVAILABLE",
        timeout_s=900,
        interval_s=15,
    )
    assert rebooted["status"] == "AVAILABLE", f"expected AVAILABLE after reboot, got {rebooted['status']!r}"


def _error_detail(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _delete_instance_if_present(ctx, instance_id):
    from botocore.exceptions import ClientError

    influx = ctx.client("timestream-influxdb")
    try:
        influx.delete_db_instance(identifier=instance_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _ensure_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region to provision Timestream for InfluxDB "
            "networking prerequisites (would need a custom VPC/subnet/route-table setup)"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if len(subnets) < 2:
        raise AssertionError("shared network does not have at least 2 shared-network subnet")
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]
    sg_name = ctx.unique_name("sim2real-influxdb-sg-")
    sg_id = ec2.create_security_group(
        GroupName=sg_name,
        Description="sim2real timestream-influxdb behavioral check",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "true"}]}
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id))
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "security_group_id": sg_id}


def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
