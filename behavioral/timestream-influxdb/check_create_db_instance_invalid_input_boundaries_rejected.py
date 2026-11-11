"""create-db-instance-invalid-input-boundaries-rejected."""
from __future__ import annotations

import secrets
import time

from behavioral_harness import tags

CHECK = "create-db-instance-invalid-input-boundaries-rejected"
GROUP = "overly-permissive"
SERVICES = ["timestream-influxdb"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDbInstance rejects a password that fails the alphanumeric pattern and an
    allocatedStorage below the 20 GiB minimum, both with ValidationException and without
    creating any instance, while a fully valid request (positive control) succeeds."""
    net = _ensure_network(ctx)
    influx = ctx.client("timestream-influxdb")
    # allocatedStorage's 20 GiB minimum is a shape-level `min` in the Smithy model, so a normal
    # boto3 client rejects it locally (ParamValidationError, never a ClientError) before any
    # request reaches the service -- that would test the SDK, not CreateDbInstance's own
    # server-side enforcement. The password pattern is NOT locally validated by botocore (no
    # regex check in botocore.validate), so that sub-case can use the normal client.
    raw_influx = _raw_client(ctx, "timestream-influxdb")

    bad_password_name = ctx.unique_name("sim2real-badpw-")
    err = _client_error(
        lambda: influx.create_db_instance(
            name=bad_password_name,
            password="bad-pass!1",  # violates ^[a-zA-Z0-9]+$
            dbInstanceType="db.influx.medium",
            vpcSubnetIds=net["subnet_ids"],
            vpcSecurityGroupIds=[net["security_group_id"]],
            allocatedStorage=20,
            dbStorageType="InfluxIOIncludedT1",
            deploymentType="SINGLE_AZ",
            tags={"sim2real": "1"},
        )
    )
    assert err["Code"] == "ValidationException", (
        f"expected ValidationException for bad password, got {err['Code']!r}"
    )
    expected_message = (
        "1 validation error(s) detected: Value at 'password' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [a-zA-Z0-9]+"
    )
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    bad_storage_name = ctx.unique_name("sim2real-badstorage-")
    err = _client_error(
        lambda: raw_influx.create_db_instance(
            name=bad_storage_name,
            password=secrets.token_hex(12),
            dbInstanceType="db.influx.medium",
            vpcSubnetIds=net["subnet_ids"],
            vpcSecurityGroupIds=[net["security_group_id"]],
            allocatedStorage=5,  # below the 20 GiB minimum
            dbStorageType="InfluxIOIncludedT1",
            deploymentType="SINGLE_AZ",
            tags={"sim2real": "1"},
        )
    )
    assert err["Code"] == "ValidationException", (
        f"expected ValidationException for tiny storage, got {err['Code']!r}"
    )
    expected_message = (
        "1 validation error(s) detected: Value at 'allocatedStorage' failed to satisfy "
        "constraint: Member must have value greater than or equal to 20"
    )
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    matching = [
        i
        for i in _list_all_instances(influx)
        if i["name"] in (bad_password_name, bad_storage_name)
    ]
    assert matching == [], f"rejected creates must not have created any instance: {matching!r}"

    # Positive control: an otherwise identical, fully valid request succeeds.
    valid_name = ctx.unique_name("sim2real-validinput-")
    valid = influx.create_db_instance(
        name=valid_name,
        password=secrets.token_hex(12),
        dbInstanceType="db.influx.medium",
        vpcSubnetIds=net["subnet_ids"],
        vpcSecurityGroupIds=[net["security_group_id"]],
        allocatedStorage=20,
        dbStorageType="InfluxIOIncludedT1",
        deploymentType="SINGLE_AZ",
        tags={"sim2real": "1"},
    )
    instance_id = valid["id"]
    ctx.on_cleanup(lambda: _delete_instance_if_present(ctx, instance_id))
    assert valid["status"] == "CREATING", f"expected CREATING immediately after create, got {valid['status']!r}"
    final = _poll_until(
        lambda: influx.get_db_instance(identifier=instance_id),
        lambda r: r["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=2400,
        interval_s=30,
    )
    assert final["status"] == "AVAILABLE", (
        f"the valid request must reach AVAILABLE, got terminal status {final['status']!r}"
    )


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
    """A client with client-side parameter validation disabled, so a shape-level `min`/`max`
    constraint is actually sent to the TARGET and the SERVER's rejection is observed, instead of
    boto3 raising a local ParamValidationError before any request is made. Built through
    `ctx.client(..., config=...)`, which MERGES this over the runner's base config, so the client
    keeps the target's endpoint, credentials, region and TLS settings."""
    from botocore.config import Config

    return ctx.client(service, config=Config(parameter_validation=False))


def _list_all_instances(influx):
    items = []
    next_token = None
    for _ in range(20):
        kwargs = {"maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = influx.list_db_instances(**kwargs)
        items.extend(resp.get("items", []))
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return items


def _delete_instance_if_present(ctx, instance_id, timeout_s=600.0):
    """Delete the instance and wait until it is gone, so its network interfaces are released
    before the security group's own cleanup runs. DeleteDbInstance refuses with
    ValidationException or ConflictException while a create is still running; that refusal is retried."""
    from botocore.exceptions import ClientError

    influx = ctx.client("timestream-influxdb")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = influx.get_db_instance(identifier=instance_id)["status"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if status == "DELETED":
            return
        if status != "DELETING":
            try:
                influx.delete_db_instance(identifier=instance_id)
            except ClientError as err:
                code = err.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code not in ("ValidationException", "ConflictException") or time.monotonic() >= deadline:
                    raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"instance {instance_id} still {status} after {timeout_s}s of cleanup")
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
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
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
