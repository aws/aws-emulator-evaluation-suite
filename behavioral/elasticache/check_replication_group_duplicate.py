"""replication-group-duplicate."""
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
    """Call fn(); return (code, message) from the ClientError it must raise.

    An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

def _assert_error(fn, expected):
    """Assert fn() fails with `expected` (Fault/Exception-suffix normalized); return the message."""
    code, message = _error(fn)
    assert _fault_base(code) == _fault_base(expected), f"expected {expected}, got {code}"
    return message

def _describe_one(fn, list_key, id_field, id_value, **extra):
    """describe wrapper: return the single item, None on NotFound / empty list."""
    try:
        resp = fn(**{id_field: id_value}, **extra)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code") or ""
        if "NotFound" in code:
            return None
        raise
    items = resp.get(list_key, [])
    return items[0] if items else None

def _poll(probe, predicate, timeout_s=600, interval_s=15):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")
        time.sleep(interval_s)

def _wait_status(fn, list_key, id_field, id_value, status_field, target, timeout_s=1800, interval_s=15, **extra):
    return _poll(
        lambda: _describe_one(fn, list_key, id_field, id_value, **extra),
        lambda item: item is not None and item.get(status_field) == target,
        timeout_s, interval_s,
    )

def _wait_rg_status(ec, rg_id, status, timeout_s=2400, interval_s=15):
    return _wait_status(ec.describe_replication_groups, "ReplicationGroups", "ReplicationGroupId", rg_id, "Status", status, timeout_s, interval_s)

def _delete_rg_tolerant(ec, rg_id):
    """Teardown delete; the check deletes the group itself, so not-found is the normal case."""
    try:
        ec.delete_replication_group(ReplicationGroupId=rg_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ReplicationGroupNotFoundFault":
            raise

CHECK = "replication-group-duplicate"
GROUP = 'replication-group'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a replication group with an already-used ReplicationGroupId fails, a creating
    group rejects mutation, and once deleted the group is gone (NotFound on read) and unusable
    (NotFound on a mutation against the dead id)."""
    ec = ctx.client("elasticache")
    rg_id = ctx.unique_name("sim2real-behav-erg-dup-")
    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="fidelity check dup",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=1,
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_rg_tolerant(ec, rg_id))

    message = _assert_error(lambda: ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="fidelity check dup 2",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=1,
        CacheSubnetGroupName=subnet_group,
    ), "ReplicationGroupAlreadyExistsFault")
    assert message == "Replication group with specified name already exists.", message

    # A creating replication group is not a valid target for mutations.
    message = _assert_error(lambda: ec.modify_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="nope",
        ApplyImmediately=True,
    ), "InvalidReplicationGroupStateFault")
    assert message == "Replication group must be in available state to modify.", message

    _wait_rg_status(ec, rg_id, "available", timeout_s=1800)
    ec.delete_replication_group(ReplicationGroupId=rg_id)

    _poll(
        lambda: _describe_one(ec.describe_replication_groups, "ReplicationGroups", "ReplicationGroupId", rg_id),
        lambda item: item is None,
        timeout_s=900, interval_s=15,
    )
    # Gone: an independent read reports the specific not-found code.
    message = _assert_error(
        lambda: ec.describe_replication_groups(ReplicationGroupId=rg_id),
        "ReplicationGroupNotFoundFault",
    )
    assert message == f"ReplicationGroup {rg_id} not found.", message
    # Unusable: a mutation against the dead id fails the same way, not silently.
    message = _assert_error(lambda: ec.modify_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="nope",
        ApplyImmediately=True,
    ), "ReplicationGroupNotFoundFault")
    assert message == f"Replication group '{rg_id}' not found", message


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
