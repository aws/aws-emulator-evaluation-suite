"""replication-group-lifecycle."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

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

def _error(fn):
    """Return (code, message) of the ClientError ``fn`` raises; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED with {result!r}")

def _delete_rg_if_present(ec, rg_id):
    """Cleanup: delete the group unless the check already deleted it."""
    try:
        ec.delete_replication_group(ReplicationGroupId=rg_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ReplicationGroupNotFoundFault":
            raise

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

def _wait_deleted(fn, list_key, id_field, id_value, timeout_s=1800, interval_s=15, **extra):
    return _poll(
        lambda: _describe_one(fn, list_key, id_field, id_value, **extra),
        lambda item: item is None,
        timeout_s, interval_s,
    )

def _describe_rg(ec, rg_id):
    return _describe_one(ec.describe_replication_groups, "ReplicationGroups", "ReplicationGroupId", rg_id)

def _wait_rg_status(ec, rg_id, status, timeout_s=2400, interval_s=15):
    return _wait_status(ec.describe_replication_groups, "ReplicationGroups", "ReplicationGroupId", rg_id, "Status", status, timeout_s, interval_s)

def _wait_rg_deleted(ec, rg_id, timeout_s=2400, interval_s=15):
    return _wait_deleted(ec.describe_replication_groups, "ReplicationGroups", "ReplicationGroupId", rg_id, timeout_s, interval_s)

CHECK = "replication-group-lifecycle"
GROUP = 'replication-group'
SERVICES = ['elasticache']

@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A replication group goes creating -> available with a primary node group, accepts ModifyReplicationGroup, then goes deleting -> gone and its id is refused afterwards."""
    ec = ctx.client("elasticache")
    rg_id = ctx.unique_name("sim2real-behav-erg-")
    subnet_group = _network_cache_subnet_group(ctx, ec)
    created = ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="fidelity check primary",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=1,
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real", "Value": CHECK},
        ],
        CacheSubnetGroupName=subnet_group,
    )["ReplicationGroup"]
    ctx.on_cleanup(lambda: _delete_rg_if_present(ec, rg_id))
    assert created["Status"] == "creating", created["Status"]

    rg = _wait_rg_status(ec, rg_id, "available", timeout_s=1800)
    assert rg is not None, "replication group never reached available"
    assert rg["ReplicationGroupId"] == rg_id, f"expected {rg_id}, got {rg['ReplicationGroupId']}"
    node_groups = rg.get("NodeGroups", [])
    assert len(node_groups) >= 1, "expected at least one node group"
    assert node_groups[0].get("Status") == "available", f"expected available, got {node_groups[0].get('Status')!r}"
    assert len(rg.get("MemberClusters", [])) == 1, rg.get("MemberClusters")

    new_desc = "fidelity check modified description"
    ec.modify_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription=new_desc,
        ApplyImmediately=True,
    )
    updated = _poll(
        lambda: _describe_rg(ec, rg_id),
        lambda r: r is not None and r.get("Description") == new_desc and r.get("Status") == "available",
        600, 15,
    )
    assert updated["Description"] == new_desc, f"expected {new_desc!r}, got {updated['Description']!r}"

    ec.delete_replication_group(ReplicationGroupId=rg_id)
    deleting = _describe_rg(ec, rg_id)
    assert deleting is not None and deleting["Status"] == "deleting", deleting
    _wait_rg_deleted(ec, rg_id, timeout_s=900)
    assert _describe_rg(ec, rg_id) is None, "replication group still describable after delete completed"

    dead_error, dead_message = _error(
        lambda: ec.modify_replication_group(
            ReplicationGroupId=rg_id, ApplyImmediately=True, ReplicationGroupDescription="post-delete"
        )
    )
    assert dead_error == "ReplicationGroupNotFoundFault", f"expected ReplicationGroupNotFoundFault on deleted id, got {dead_error!r}"
    assert dead_message == f"Replication group '{rg_id}' not found", f"unexpected ReplicationGroupNotFoundFault message: {dead_message!r}"


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
