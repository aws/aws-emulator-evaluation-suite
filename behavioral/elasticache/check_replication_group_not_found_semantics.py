"""replication-group-not-found-semantics."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code

def _error(fn):
    """Call fn(), which must raise a ClientError; return its (Error.Code, Error.Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected a ClientError but the call SUCCEEDED")

def _assert_error(fn, expected, message):
    """Assert fn() fails with `expected` (Fault/Exception-suffix normalized) and exactly `message`."""
    code, actual = _error(fn)
    assert _fault_base(code) == _fault_base(expected), f"expected {expected}, got {code} ({actual!r})"
    assert actual == message, f"{expected}: expected message {message!r}, got {actual!r}"
    return code

CHECK = "replication-group-not-found-semantics"
GROUP = 'replication-group'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Every replication-group mutation on an unknown id raises ReplicationGroupNotFoundFault,
    while the identical Describe/Delete calls succeed on a real group, so a target refusing
    every call cannot pass."""
    ec = ctx.client("elasticache")
    bogus = ctx.unique_name("sim2real-behav-erg-missing-")

    # Positive control. TestFailover's and ModifyReplicationGroupShardConfiguration's own positive
    # paths are exercised elsewhere; standing up a multi-node / cluster-mode topology here just to
    # positive-control those two calls would be out of proportion to what this check verifies, so
    # Describe+Delete carry the control.
    real_id = ctx.unique_name("sim2real-behav-erg-real-")
    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_replication_group(
        ReplicationGroupId=real_id,
        ReplicationGroupDescription="sim2real behavioral not-found positive control",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=1,
        AutomaticFailoverEnabled=False,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_if_present(ec, real_id))

    control = ec.describe_replication_groups(ReplicationGroupId=real_id)["ReplicationGroups"][0]
    assert control["ReplicationGroupId"] == real_id, (
        f"expected positive control to describe {real_id}, got {control.get('ReplicationGroupId')}"
    )

    _assert_error(
        lambda: ec.describe_replication_groups(ReplicationGroupId=bogus),
        "ReplicationGroupNotFoundFault",
        f"ReplicationGroup {bogus} not found.",
    )
    _assert_error(
        lambda: ec.delete_replication_group(ReplicationGroupId=bogus),
        "ReplicationGroupNotFoundFault",
        "Specified replication group does not exist",
    )
    _assert_error(
        lambda: ec.test_failover(
            ReplicationGroupId=bogus, NodeGroupId="0001",
        ),
        "ReplicationGroupNotFoundFault",
        f"Replication group {bogus} does not exist.",
    )
    _assert_error(
        lambda: ec.modify_replication_group_shard_configuration(
            ReplicationGroupId=bogus, NodeGroupCount=2, ApplyImmediately=True,
        ),
        "ReplicationGroupNotFoundFault",
        f"Replication group '{bogus}' not found",
    )

    # Close the positive-control loop: DeleteReplicationGroup, which just failed against
    # `bogus`, succeeds against the real id -- and the deleted id then reports NotFound too.
    real = _wait_available(ec, real_id, timeout_s=1200.0)
    assert real["Status"] == "available", f"expected available, got {real['Status']!r}"
    ec.delete_replication_group(ReplicationGroupId=real_id)
    waiter = ec.get_waiter("replication_group_deleted")
    waiter.wait(ReplicationGroupId=real_id, WaiterConfig={"Delay": 2, "MaxAttempts": 600})
    not_found_code, not_found_message = _error(
        lambda: ec.describe_replication_groups(ReplicationGroupId=real_id)
    )
    assert not_found_code == "ReplicationGroupNotFoundFault", f"expected NotFound, got {not_found_code!r}"
    assert not_found_message == f"ReplicationGroup {real_id} not found.", (
        f"expected the deleted group's exact NotFound message, got {not_found_message!r}"
    )


# ===== helpers =====

def _wait_available(ec, rg_id, timeout_s=1200.0):
    """Poll until `rg_id` reaches 'available'; raise (never return a stale status) on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        rg = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"][0]
        last = rg
        if rg["Status"] == "available":
            return rg
        time.sleep(2)
    raise AssertionError(f"replication group {rg_id} never reached available, last={last}")


def _delete_if_present(ec, rg_id):
    """Teardown when `run()` raised before its own delete: retry while the group is still
    creating, then wait for it to go; with the subnet group it fits the 1800 s cleanup budget."""
    _delete_when_released(
        lambda: ec.delete_replication_group(ReplicationGroupId=rg_id),
        ("InvalidReplicationGroupState",),
        ("ReplicationGroupNotFoundFault",),
        timeout_s=600.0,
        interval_s=2.0,
    )
    waiter = ec.get_waiter("replication_group_deleted")
    waiter.wait(ReplicationGroupId=rg_id, WaiterConfig={"Delay": 2, "MaxAttempts": 300})


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
            timeout_s=540.0,
            interval_s=2.0,
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a resource, retrying while it reports one of ``busy_codes``."""
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
