"""describe-events-window."""
from __future__ import annotations

import time
from datetime import timedelta
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code

def _error(fn, expected):
    """Call fn() and return its ClientError (code, message); raise if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected {expected} but the call SUCCEEDED")

def _assert_error(fn, expected):
    """Assert fn() fails with the (code, message) pair `expected`: the code Fault/Exception-suffix
    normalized, the message exact; return the code."""
    code, got = _error(fn, expected[0])
    assert _fault_base(code) == _fault_base(expected[0]), f"expected {expected[0]}, got {code}"
    assert got == expected[1], f"{expected[0]}: expected message {expected[1]!r}, got {got!r}"
    return code

CHECK = "describe-events-window"
GROUP = 'discovery'
SERVICES = ['elasticache']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeEvents bounds its result to the requested StartTime/EndTime window —
    a real event is visible when the window spans it and absent when the window ends
    before it occurred — and rejects a MaxRecords value below the documented minimum."""
    ec = ctx.client("elasticache")
    cluster_id = ctx.unique_name("sim2real-behav-evw-")
    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_cache_cluster(
        CacheClusterId=cluster_id,
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: ec.delete_cache_cluster(CacheClusterId=cluster_id))
    _wait_for_available(ec, cluster_id, timeout_s=600)

    events = _poll_for_events(ec, cluster_id, timeout_s=180)
    assert events, f"no events recorded for {cluster_id} within the poll window"
    for e in events:
        assert e.get("SourceType") == "cache-cluster", e
        assert e.get("SourceIdentifier") == cluster_id, e
        assert e.get("Date") is not None, e

    earliest = min(e["Date"] for e in events)
    latest = max(e["Date"] for e in events)

    # A window that spans the events must include them.
    spanning = ec.describe_events(
        SourceIdentifier=cluster_id,
        SourceType="cache-cluster",
        StartTime=earliest - timedelta(minutes=5),
        EndTime=latest + timedelta(minutes=5),
        MaxRecords=20,
    )["Events"]
    assert spanning, (
        f"DescribeEvents returned no events for {cluster_id} within a window that "
        f"spans its known events ({earliest} .. {latest})"
    )

    # A window that ends before the earliest known event must exclude it — the
    # window bound, not just the SourceIdentifier filter, does the excluding.
    excluded = ec.describe_events(
        SourceIdentifier=cluster_id,
        SourceType="cache-cluster",
        StartTime=earliest - timedelta(hours=1),
        EndTime=earliest - timedelta(seconds=1),
        MaxRecords=20,
    )["Events"]
    assert excluded == [], (
        f"DescribeEvents returned events for {cluster_id} with EndTime before its "
        f"earliest known event: {excluded}"
    )

    # MaxRecords below the documented minimum is rejected.
    _assert_error(
        lambda: ec.describe_events(MaxRecords=1),
        ("InvalidParameterValueException",
        "Invalid value for max records. Must be between 20 and 100"),
    )


def _wait_for_available(ec: Any, cluster_id: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = ec.describe_cache_clusters(CacheClusterId=cluster_id)
        last_status = resp["CacheClusters"][0]["CacheClusterStatus"]
        if last_status == "available":
            return
        time.sleep(2)
    raise AssertionError(
        f"cluster {cluster_id} did not become available within {timeout_s}s "
        f"(last observed: {last_status!r})"
    )


def _poll_for_events(ec: Any, source_id: str, timeout_s: float) -> list[dict]:
    deadline = time.monotonic() + timeout_s
    last: list[dict] = []
    while time.monotonic() < deadline:
        resp = ec.describe_events(
            SourceIdentifier=source_id, SourceType="cache-cluster", MaxRecords=20
        )
        last = resp["Events"]
        if last:
            return last
        time.sleep(5)
    return last


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
