"""create-replication-group-authtoken-without-transit-encryption-rejected."""
from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-replication-group-authtoken-without-transit-encryption-rejected"
GROUP = "overly-permissive"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateReplicationGroup with an AuthToken but TransitEncryptionEnabled unset/false is rejected
    with InvalidParameterValue (an AuthToken needs transit encryption) and creates nothing; the same
    request with TransitEncryptionEnabled=True succeeds."""
    ec = ctx.client("elasticache")
    ec2 = ctx.client("ec2")

    bad_rg_id = ctx.unique_name("sim2real-bad-")
    good_rg_id = ctx.unique_name("sim2real-good-")
    token = secrets.token_urlsafe(24)
    ctx.on_cleanup(lambda: _delete_replication_group(ec, bad_rg_id))
    subnet_group_name = _create_subnet_group(ctx, ec, ec2)
    sg_id = _open_security_group(ctx, ec2, 6379)


    subnet_group = _network_cache_subnet_group(ctx, ec)
    code, message = _error(
        lambda: ec.create_replication_group(
            ReplicationGroupId=bad_rg_id,
            ReplicationGroupDescription="authtoken without transit encryption",
            Engine="redis",
            CacheNodeType="cache.t3.micro",
            NumCacheClusters=1,
            AuthToken=token,
            CacheSubnetGroupName=subnet_group,
        )
    )
    assert code == "InvalidParameterValue", (
        "CreateReplicationGroup with AuthToken but no TransitEncryptionEnabled was refused "
        f"with an unexpected error code {code!r}"
    )
    assert message == "The AUTH token is only supported when encryption-in-transit is enabled", f"unexpected {code} message: {message!r}"

    # Effect absent: the replication group must not have been created.
    notfound_code, notfound_message = _error(
        lambda: ec.describe_replication_groups(ReplicationGroupId=bad_rg_id)
    )
    assert notfound_code == "ReplicationGroupNotFoundFault", (
        f"rejected replication group {bad_rg_id!r} should not exist; "
        f"describe_replication_groups returned error code {notfound_code!r}"
    )
    expected_not_found = f"ReplicationGroup {bad_rg_id} not found."
    assert notfound_message == expected_not_found, (
        f"expected message {expected_not_found!r}, got {notfound_message!r}"
    )

    # Positive control: the identical request succeeds once TransitEncryptionEnabled=True
    # is added, proving the rejection above was specific to that one missing field.
    try:
        ec.create_replication_group(
            ReplicationGroupId=good_rg_id,
            ReplicationGroupDescription="authtoken with transit encryption",
            Engine="redis",
            CacheNodeType="cache.t3.micro",
            NumCacheClusters=1,
            AuthToken=token,
            TransitEncryptionEnabled=True,
            CacheSubnetGroupName=subnet_group_name,
            SecurityGroupIds=[sg_id],
        )
    except Exception as exc:  # noqa: BLE001 - surface the full message for diagnosis
        raise AssertionError(str(exc)) from None
    ctx.on_cleanup(lambda: _delete_replication_group(ec, good_rg_id))

    rg = _poll_until(
        lambda: ec.describe_replication_groups(ReplicationGroupId=good_rg_id)[
            "ReplicationGroups"
        ][0],
        lambda r: r["Status"] == "available",
        timeout_s=900,
        interval_s=20,
    )
    assert rg["Status"] == "available", f"expected status 'available', got {rg['Status']!r}"
    assert rg["AuthTokenEnabled"] is True, (
        f"expected AuthTokenEnabled=True on {good_rg_id!r}, got {rg.get('AuthTokenEnabled')!r}"
    )
    assert rg["TransitEncryptionEnabled"] is True, (
        f"expected TransitEncryptionEnabled=True on {good_rg_id!r}, "
        f"got {rg.get('TransitEncryptionEnabled')!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) from the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED with {result!r}")


def _create_subnet_group(ctx, ec, ec2) -> str:
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnet_ids = [s["SubnetId"] for s in subnets][:3]
    name = ctx.unique_name("sim2real-ec-sng-")
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="sim2real behavioral check",
        SubnetIds=subnet_ids,
    )
    ctx.on_cleanup(lambda: ec.delete_cache_subnet_group(CacheSubnetGroupName=name))
    return name


def _open_security_group(ctx, ec2, port: int) -> str:
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    name = ctx.unique_name("sim2real-ec-sg-")
    sg_id = ec2.create_security_group(
        GroupName=name, Description="sim2real elasticache behavioral check", VpcId=vpc_id
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id))
    return sg_id


def _poll_until(probe, predicate, timeout_s=900, interval_s=15):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _delete_replication_group(ec, rg_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        rg = _poll_until(
            lambda: ec.describe_replication_groups(ReplicationGroupId=rg_id)[
                "ReplicationGroups"
            ][0],
            lambda r: r["Status"] == "available",
            timeout_s=600,
            interval_s=20,
        )
        assert rg["Status"] == "available", (
            f"cannot delete {rg_id!r} before it reaches 'available'; got {rg['Status']!r}"
        )
        ec.delete_replication_group(ReplicationGroupId=rg_id)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ReplicationGroupNotFoundFault":
            return
        raise
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        try:
            ec.describe_replication_groups(ReplicationGroupId=rg_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ReplicationGroupNotFoundFault":
                return
            raise
        time.sleep(20)



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


def _network_cache_subnet_group(ctx, client) -> str:
    """An ElastiCache subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-csg-")
    client.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_cache_subnet_group(CacheSubnetGroupName=name),
            # DeleteCacheSubnetGroup refuses a group a cluster still holds with CacheSubnetGroupInUse.
            ("CacheSubnetGroupInUse", "InvalidCacheSubnetGroupState"),
            ("CacheSubnetGroupNotFoundFault",),
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
