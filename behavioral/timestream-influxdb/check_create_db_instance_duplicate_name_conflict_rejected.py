"""create-db-instance-duplicate-name-conflict-rejected."""
from __future__ import annotations

import secrets
import time

from behavioral_harness import tags

CHECK = "create-db-instance-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["timestream-influxdb"]


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A second CreateDbInstance with a name in use fails with ConflictException and the exact "already exists"
    message, and the original stays the only instance with that name; once the original is deleted, the
    identical call creates a new instance that owns the name and reaches AVAILABLE."""
    teardown_deadline: dict = {}
    net = _ensure_network(ctx, teardown_deadline)
    influx = ctx.client("timestream-influxdb")
    name = ctx.unique_name("sim2real-dupname-")
    check_tags = {"sim2real": CHECK}

    def _create(password):
        return influx.create_db_instance(
            name=name,
            password=password,
            dbInstanceType="db.influx.medium",
            vpcSubnetIds=net["subnet_ids"],
            vpcSecurityGroupIds=[net["security_group_id"]],
            allocatedStorage=20,
            dbStorageType="InfluxIOIncludedT1",
            deploymentType="SINGLE_AZ",
            tags=check_tags,
        )

    first = _create(secrets.token_hex(12))
    instance_id = first["id"]
    ctx.on_cleanup(lambda: _delete_instance_if_present(ctx, instance_id, teardown_deadline))
    # positive control: the first create succeeded and returned the instance it owns
    assert first["status"] == "CREATING", f"expected CREATING, got {first['status']!r}"
    assert first["name"] == name, f"expected the created instance to carry name {name!r}, got {first['name']!r}"

    # Break exactly one thing: reuse the same name while the original still owns it.
    err = _client_error(lambda: _create(secrets.token_hex(12)))
    assert err["Code"] == "ConflictException", f"expected ConflictException, got {err['Code']!r}"
    expected_message = (
        f"The DbInstance with id [{instance_id}], name [{name}], customer [{ctx.account}] "
        "already exists"
    )
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Effect absent: an independent read shows the rejected duplicate created nothing.
    matching = [i for i in _list_all_instances(influx) if i["name"] == name]
    assert len(matching) == 1, f"duplicate create must not have created a second instance: {matching!r}"
    assert matching[0]["id"] == instance_id, (
        f"expected the surviving instance to be the original {instance_id!r}, got {matching[0]['id']!r}"
    )

    # Restore: the name conflict is a state (a live instance owns the name), not an
    # always-invalid input -- freeing the name by deleting the original lets the
    # identical call that was just rejected succeed.
    available = _poll_until(
        lambda: influx.get_db_instance(identifier=instance_id),
        lambda r: r["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=2400,
        interval_s=30,
    )
    assert available["status"] == "AVAILABLE", (
        f"original instance reached terminal status {available['status']!r} instead of AVAILABLE"
    )

    influx.delete_db_instance(identifier=instance_id)
    _poll_until(
        lambda: _describe_or_none(influx, instance_id),
        lambda r: r is None or r["status"] == "DELETED",
        timeout_s=1800,
        interval_s=20,
    )

    restored = _create(secrets.token_hex(12))
    restored_id = restored["id"]
    ctx.on_cleanup(lambda: _delete_instance_if_present(ctx, restored_id, teardown_deadline))
    assert restored["status"] == "CREATING", (
        f"identical create must succeed once the name is freed, got status {restored['status']!r}"
    )
    assert restored["name"] == name, (
        f"identical create must succeed once the name is freed, got name {restored['name']!r}"
    )
    assert restored_id != instance_id, "restored instance must be a new resource, not the deleted one"

    restored_matching = [i for i in _list_all_instances(influx) if i["name"] == name]
    assert len(restored_matching) == 1, (
        f"exactly one instance should own the freed name after restore: {restored_matching!r}"
    )
    assert restored_matching[0]["id"] == restored_id, (
        f"expected the restored instance {restored_id!r} to own the name, got {restored_matching[0]['id']!r}"
    )

    restored_final = _poll_until(
        lambda: influx.get_db_instance(identifier=restored_id),
        lambda r: r["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=2400,
        interval_s=30,
    )
    assert restored_final["status"] == "AVAILABLE", (
        f"restored instance reached terminal status {restored_final['status']!r} instead of AVAILABLE"
    )


def _client_error(fn):
    """Call fn(); return the botocore Error dict (Code and Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected rejection, but the call succeeded and returned {result!r}")


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


def _describe_or_none(influx, instance_id):
    from botocore.exceptions import ClientError

    try:
        return influx.get_db_instance(identifier=instance_id)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


# One cleanup deadline (seconds) shared by every teardown in this check.
_TEARDOWN_RETRY_S = 900.0


def _teardown_left(teardown_deadline) -> float:
    """Seconds left before the run's shared cleanup deadline."""
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 120.0)
    return max(0.0, deadline - time.monotonic())


def _delete_instance_if_present(ctx, instance_id, teardown_deadline):
    """Wait out a create in progress, delete the instance, and wait until it is gone, so its
    network interfaces are released before the security group's own cleanup runs; every wait
    ends at the shared cleanup deadline."""
    from botocore.exceptions import ClientError

    influx = ctx.client("timestream-influxdb")
    current = _describe_or_none(influx, instance_id)
    if current is not None and current["status"] not in ("DELETING", "DELETED"):
        if current["status"] not in ("AVAILABLE", "FAILED"):
            _poll_until(
                lambda: _describe_or_none(influx, instance_id),
                lambda r: r is None or r["status"] in ("AVAILABLE", "FAILED", "DELETING", "DELETED"),
                timeout_s=_teardown_left(teardown_deadline),
                interval_s=30,
            )
        try:
            influx.delete_db_instance(identifier=instance_id)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    _poll_until(
        lambda: _describe_or_none(influx, instance_id),
        lambda r: r is None or r["status"] == "DELETED",
        timeout_s=_teardown_left(teardown_deadline),
        interval_s=20,
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _ensure_network(ctx, teardown_deadline):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in the region to provision Timestream for InfluxDB "
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
            {"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id, teardown_deadline))
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "security_group_id": sg_id}


def _delete_security_group_when_free(ec2, sg_id, teardown_deadline, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + _teardown_left(teardown_deadline)
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
