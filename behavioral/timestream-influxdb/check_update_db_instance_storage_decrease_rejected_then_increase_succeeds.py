"""update-db-instance-storage-decrease-rejected-then-increase-succeeds."""
from __future__ import annotations

import secrets
import time

from behavioral_harness import tags

CHECK = "update-db-instance-storage-decrease-rejected-then-increase-succeeds"
GROUP = "overly-permissive"
SERVICES = ["timestream-influxdb"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDbInstance rejects shrinking allocatedStorage below the 20 GiB floor with a
    server-side ValidationException and leaves the instance unchanged, while a valid
    increase succeeds and persists (positive control)."""
    net = _ensure_network(ctx)
    influx = ctx.client("timestream-influxdb")
    raw_influx = _raw_client(ctx, "timestream-influxdb")
    name = ctx.unique_name("sim2real-storageupdate-")
    created = influx.create_db_instance(
        name=name,
        password=secrets.token_hex(12),
        dbInstanceType="db.influx.medium",
        vpcSubnetIds=net["subnet_ids"],
        vpcSecurityGroupIds=[net["security_group_id"]],
        allocatedStorage=20,
        dbStorageType="InfluxIOIncludedT1",
        deploymentType="SINGLE_AZ",
        tags={"sim2real-check": CHECK},
    )
    instance_id = created["id"]
    ctx.on_cleanup(lambda: _delete_instance_if_present(ctx, instance_id))

    available = _poll_until(
        lambda: influx.get_db_instance(identifier=instance_id),
        lambda r: r["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=2400,
        interval_s=30,
    )
    assert available["status"] == "AVAILABLE", f"expected AVAILABLE, got {available['status']!r}"
    assert available["allocatedStorage"] == 20, f"expected initial allocatedStorage 20, got {available['allocatedStorage']!r}"

    # Break exactly one thing: attempt to shrink storage below the floor.
    err = _client_error(lambda: raw_influx.update_db_instance(identifier=instance_id, allocatedStorage=10))
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err['Code']!r}"
    expected_message = (
        "1 validation error(s) detected: Value at 'allocatedStorage' failed to satisfy "
        "constraint: Member must have value greater than or equal to 20"
    )
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )
    unchanged = influx.get_db_instance(identifier=instance_id)
    assert unchanged["allocatedStorage"] == 20, "rejected shrink must not change allocatedStorage"
    assert unchanged["status"] == "AVAILABLE", f"expected status to remain AVAILABLE after rejected shrink, got {unchanged['status']!r}"

    # Positive control: a valid increase succeeds and persists.
    influx.update_db_instance(identifier=instance_id, allocatedStorage=40)
    updated = _poll_until(
        lambda: influx.get_db_instance(identifier=instance_id),
        lambda r: r["status"] == "AVAILABLE" and r["allocatedStorage"] == 40,
        timeout_s=1800,
        interval_s=20,
    )
    assert updated["allocatedStorage"] == 40, f"expected allocatedStorage 40 after increase, got {updated['allocatedStorage']!r}"


# ===== helpers =====

def _client_error(fn):
    """Call fn(); return the botocore Error dict (Code and Message). An unexpected SUCCESS
    raises its own AssertionError, so an accepted call that AWS refuses is reported as an
    unexpected success rather than as a code or message mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _raw_client(ctx, service: str):
    """A client with client-side parameter validation disabled, so the shape-level `min`
    constraint is sent to the TARGET and the SERVER's rejection is observed, instead of boto3
    raising a local ParamValidationError before any request is made. Built through
    `ctx.client(..., config=...)`, which keeps the target's endpoint, credentials and region."""
    from botocore.config import Config

    return ctx.client(service, config=Config(parameter_validation=False))


def _describe_or_none(influx, instance_id):
    from botocore.exceptions import ClientError

    try:
        return influx.get_db_instance(identifier=instance_id)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _delete_instance_if_present(ctx, instance_id, timeout_s=840.0):
    """Delete the instance and wait until it is gone, so its network interfaces are released
    before the security group's own cleanup runs. DeleteDbInstance refuses with
    ValidationException or ConflictException while a create or update is still running; that
    refusal is retried."""
    from botocore.exceptions import ClientError

    influx = ctx.client("timestream-influxdb")
    deadline = time.monotonic() + timeout_s
    while True:
        current = _describe_or_none(influx, instance_id)
        if current is None or current["status"] == "DELETED":
            return
        if current["status"] != "DELETING":
            try:
                influx.delete_db_instance(identifier=instance_id)
            except ClientError as err:
                code = err.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code not in ("ValidationException", "ConflictException") or time.monotonic() >= deadline:
                    raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"instance {instance_id} still {current['status']} after {timeout_s}s of cleanup")
        time.sleep(2)


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
        raise AssertionError("shared network does not have at least 2 shared-network subnets")
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]
    sg_name = ctx.unique_name("sim2real-influxdb-sg-")
    sg_id = ec2.create_security_group(
        GroupName=sg_name,
        Description="sim2real timestream-influxdb behavioral check",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "sim2real-check", "Value": CHECK}]}
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
