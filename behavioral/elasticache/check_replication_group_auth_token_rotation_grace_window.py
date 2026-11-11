"""replication-group-auth-token-rotation-grace-window."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "replication-group-auth-token-rotation-grace-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """During an AuthToken ROTATE, PendingModifiedValues.AuthTokenStatus reads ROTATING on
    DescribeReplicationGroups; a subsequent SET finalizes the rotation and clears the status."""
    ec = ctx.client("elasticache")
    ec2 = ctx.client("ec2")
    rg_id = ctx.unique_name("sim2real-authrot-")
    token1 = "S1mpar1ty-Token-One-2024!"
    token2 = "S1mpar1ty-Token-Two-2024!"

    # Real AWS rejects an AuthToken create with InvalidParameterCombination ("Redis Auth can
    # only be enabled within an Amazon VPC") unless a CacheSubnetGroup places the group in one;
    # there is no ambient default that satisfies this, so one is created explicitly.
    subnet_ids = _default_subnet_ids(ec2, 2, ctx=ctx)
    sng_name = ctx.unique_name("sim2real-authrot-sng-")
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=sng_name,
        CacheSubnetGroupDescription="auth token rotation grace window subnet group",
        SubnetIds=subnet_ids,
    )
    ctx.on_cleanup(lambda: _delete_subnet_group(ec, sng_name))

    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="auth token rotation grace window test",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=1,
        TransitEncryptionEnabled=True,
        AuthToken=token1,
        CacheSubnetGroupName=sng_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ec.delete_replication_group(ReplicationGroupId=rg_id))
    _wait_rg_status(ec, rg_id, "available", timeout_s=1200)

    # DescribeReplicationGroups reporting "available" does not guarantee ModifyReplicationGroup
    # is immediately accepted -- real AWS can still answer InvalidReplicationGroupState for a
    # brief settle window right after the transition; retry through that, not around it.
    _modify_with_retry(lambda: ec.modify_replication_group(
        ReplicationGroupId=rg_id,
        AuthToken=token2,
        AuthTokenUpdateStrategy="ROTATE",
        ApplyImmediately=True,
    ))

    rotating_seen = _poll_until_pending_auth_status(ec, rg_id, "ROTATING", timeout_s=300)
    assert rotating_seen, (
        "PendingModifiedValues.AuthTokenStatus never reported ROTATING after an AuthToken "
        "ROTATE update; the dual-token grace window is not observable"
    )

    _modify_with_retry(lambda: ec.modify_replication_group(
        ReplicationGroupId=rg_id,
        AuthToken=token2,
        AuthTokenUpdateStrategy="SET",
        ApplyImmediately=True,
    ))

    finalized = _wait_rotation_finalized(ec, rg_id, timeout_s=900)
    assert finalized, "AuthToken rotation never finalized (PendingModifiedValues.AuthTokenStatus stuck)"


def _default_subnet_ids(ec2, count=2, *, ctx):
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    by_az = {}
    for subnet in resp.get("Subnets", []):
        by_az.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
    subnet_ids = [by_az[az] for az in sorted(by_az)][:count]
    if len(subnet_ids) < count:
        raise AssertionError(f"account has only {len(subnet_ids)} network subnets; need {count}")
    return subnet_ids


def _delete_subnet_group(ec, name, timeout_s=900.0, interval_s=15.0):
    """Retry while the replication group deleted just before this still references the subnet
    group (DeleteCacheSubnetGroup rejects with DependencyViolation until it fully drains)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec.delete_cache_subnet_group(CacheSubnetGroupName=name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code") or ""
            if "NotFound" in code:
                return
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _modify_with_retry(fn, timeout_s=60.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code") or ""
            if "InvalidReplicationGroupState" not in code or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _wait_rg_status(ec, rg_id, target_status, timeout_s=1200.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
        if groups and groups[0]["Status"] == target_status:
            return groups[0]
        time.sleep(interval_s)
    raise AssertionError(f"replication group {rg_id} never reached status {target_status!r} within {timeout_s}s")


def _poll_until_pending_auth_status(ec, rg_id, target_auth_status, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
        if groups:
            pending = groups[0].get("PendingModifiedValues", {})
            if pending.get("AuthTokenStatus") == target_auth_status:
                return True
        time.sleep(interval_s)
    return False


def _wait_rotation_finalized(ec, rg_id, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
        if groups:
            group = groups[0]
            pending = group.get("PendingModifiedValues", {})
            if group["Status"] == "available" and "AuthTokenStatus" not in pending:
                return True
        time.sleep(interval_s)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
