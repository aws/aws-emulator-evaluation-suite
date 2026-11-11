"""cache-subnet-group-in-use-forbidden."""
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
    """Call fn(); return (code, HTTP status, message) from the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return error.get("Code"), status, error.get("Message") or ""
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED with {result!r}")

def _assert_error(fn, expected, expected_status, subject):
    """Assert fn() fails with `expected` (Fault/Exception-suffix normalized), `expected_status`
    and a message naming `subject`; return the code and the message."""
    code, status, message = _error(fn)
    assert _fault_base(code) == _fault_base(expected), f"expected {expected}, got {code}"
    assert status == expected_status, f"expected HTTP {expected_status} for {expected}, got {status}"
    assert subject in message, f"expected the {expected} message to name {subject!r}, got {message!r}"
    return code, message

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

def _wait_deleted(fn, list_key, id_field, id_value, timeout_s=1800, interval_s=15, **extra):
    return _poll(
        lambda: _describe_one(fn, list_key, id_field, id_value, **extra),
        lambda item: item is None,
        timeout_s, interval_s,
    )

def _wait_cluster_status(ec, cluster_id, status, timeout_s=1800, interval_s=15):
    return _wait_status(ec.describe_cache_clusters, "CacheClusters", "CacheClusterId", cluster_id, "CacheClusterStatus", status, timeout_s, interval_s)

def _wait_cluster_deleted(ec, cluster_id, timeout_s=1800, interval_s=15):
    return _wait_deleted(ec.describe_cache_clusters, "CacheClusters", "CacheClusterId", cluster_id, timeout_s, interval_s)

def _delete_subnet_group(ec, name, timeout_s=660, interval_s=15):
    """Delete a cache subnet group, retrying while a referencing cluster is still draining."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec.delete_cache_subnet_group(CacheSubnetGroupName=name)
            return
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code") or ""
            if "NotFound" in code:
                return
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

def _delete_cluster_if_present(ec, cluster_id):
    """Teardown: delete the cluster unless the check body already removed it."""
    try:
        ec.delete_cache_cluster(CacheClusterId=cluster_id)
    except ClientError as e:
        if "NotFound" not in (e.response.get("Error", {}).get("Code") or ""):
            raise

def _default_subnet_ids(ec2, count=2, *, ctx):
    """Return `count` default-VPC subnet ids in distinct AZs (skip if too few)."""
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    by_az = {}
    for subnet in resp.get("Subnets", []):
        by_az.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
    subnet_ids = [by_az[az] for az in sorted(by_az)][:count]
    if len(subnet_ids) < count:
        raise AssertionError(f"account has only {len(subnet_ids)} network subnets; need {count}")
    return subnet_ids

# The harness's per-check budget for this suite: every wait ends only where the runner would
# stop the check anyway, so no wait is an assertion on elapsed time.
_SUITE_BUDGET_S = 3600

CHECK = "cache-subnet-group-in-use-forbidden"
GROUP = 'overly-permissive'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An unreferenced subnet group deletes; one still referenced by a cluster is refused and kept;
    once the cluster is gone the identical delete succeeds."""
    ec = ctx.client("elasticache")
    ec2 = ctx.client("ec2")
    subnet_ids = _default_subnet_ids(ec2, 2, ctx=ctx)

    # Positive control: an unreferenced twin subnet group over the same subnets deletes cleanly.
    twin = ctx.unique_name("sim2real-behav-ecsg-twin-")
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=twin,
        CacheSubnetGroupDescription="fidelity check unreferenced twin",
        SubnetIds=subnet_ids,
    )
    ctx.on_cleanup(lambda: _delete_subnet_group(ec, twin))
    ec.delete_cache_subnet_group(CacheSubnetGroupName=twin)
    assert _describe_one(ec.describe_cache_subnet_groups, "CacheSubnetGroups", "CacheSubnetGroupName", twin) is None, (
        "the unreferenced twin subnet group is still visible after its delete"
    )

    name = ctx.unique_name("sim2real-behav-ecsg-inuse-")
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="fidelity check subnet group in use",
        SubnetIds=subnet_ids,
    )
    ctx.on_cleanup(lambda: _delete_subnet_group(ec, name))

    cluster_id = ctx.unique_name("sim2real-behav-ecc-subnet-")
    ec.create_cache_cluster(
        CacheClusterId=cluster_id,
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        CacheSubnetGroupName=name,
    )
    ctx.on_cleanup(lambda: _delete_cluster_if_present(ec, cluster_id))

    # The reference is live from the moment of creation, not only once available.
    _, message = _assert_error(
        lambda: ec.delete_cache_subnet_group(CacheSubnetGroupName=name),
        "CacheSubnetGroupInUse", 400, name,
    )
    expected_message = f"Cache subnet group {name} is currently in use by a cache cluster."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    # Effect absent: the refused delete left the group in place.
    kept = _describe_one(ec.describe_cache_subnet_groups, "CacheSubnetGroups", "CacheSubnetGroupName", name)
    assert kept is not None and kept["CacheSubnetGroupName"] == name, (
        f"the refused delete removed the subnet group anyway: {kept!r}"
    )

    cluster = _wait_cluster_status(ec, cluster_id, "available", timeout_s=_SUITE_BUDGET_S)
    assert cluster["CacheSubnetGroupName"] == name, cluster

    _, message = _assert_error(
        lambda: ec.delete_cache_subnet_group(CacheSubnetGroupName=name),
        "CacheSubnetGroupInUse", 400, name,
    )
    expected_message = f"Cache subnet group {name} is currently in use by a cache cluster."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    ec.delete_cache_cluster(CacheClusterId=cluster_id)
    _wait_cluster_deleted(ec, cluster_id, timeout_s=_SUITE_BUDGET_S)

    # The reference is gone: the identical call that was twice forbidden above now succeeds.
    ec.delete_cache_subnet_group(CacheSubnetGroupName=name)
    assert _describe_one(ec.describe_cache_subnet_groups, "CacheSubnetGroups", "CacheSubnetGroupName", name) is None, (
        "subnet group still visible via an independent describe after delete"
    )
    _, message = _assert_error(
        lambda: ec.delete_cache_subnet_group(CacheSubnetGroupName=name),
        "CacheSubnetGroupNotFound", 400, name,
    )
    expected_message = f"Cache Subnet Group {name} does not exist."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
