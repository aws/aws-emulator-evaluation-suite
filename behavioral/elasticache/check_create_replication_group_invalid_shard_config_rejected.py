"""create-replication-group-invalid-shard-config-rejected."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-replication-group-invalid-shard-config-rejected"
GROUP = "error-semantics"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateReplicationGroup with both NumCacheClusters and NumNodeGroups is rejected with
    InvalidParameterCombination and its exact message and leaves no group (ReplicationGroupNotFoundFault),
    while a single-shard request becomes available."""
    ec = ctx.client("elasticache")
    good_id = ctx.unique_name("sim2real-shard-ok-")[:40].rstrip("-")
    bad_id = ctx.unique_name("sim2real-shard-bad-")[:40].rstrip("-")

    # Positive control: a conventional (non-cluster-mode) single-shard request succeeds.
    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_replication_group(
        ReplicationGroupId=good_id,
        ReplicationGroupDescription="sim2real shard-config control",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=1,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: ec.delete_replication_group(ReplicationGroupId=good_id)))
    good = _poll_until(
        lambda: _describe_rg(ec, good_id),
        lambda r: r["Status"] == "available",
        timeout_s=600.0,
        interval_s=15.0,
    )
    assert good["Status"] == "available", f"positive-control replication group never became available: {good['Status']!r}"

    # Negative: mutually inconsistent NumCacheClusters + NumNodeGroups without
    # cluster mode enabled.
    code, message = _error(
        lambda: ec.create_replication_group(
            ReplicationGroupId=bad_id,
            ReplicationGroupDescription="sim2real shard-config negative",
            Engine="redis",
            CacheNodeType="cache.t3.micro",
            NumCacheClusters=3,
            NumNodeGroups=2,
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            CacheSubnetGroupName=subnet_group,
        )
    )
    assert code == "InvalidParameterCombination", (
        f"expected InvalidParameterCombination, got {code!r}"
    )
    assert message == "NumCacheClusters can only be specified for one node group.", f"unexpected InvalidParameterCombination message: {message!r}"

    # Effect absent: the rejected replication group was never created.
    not_found_code, not_found_message = _error(
        lambda: ec.describe_replication_groups(ReplicationGroupId=bad_id)
    )
    assert not_found_code == "ReplicationGroupNotFoundFault", (
        f"rejected CreateReplicationGroup must not leave a partial resource behind, "
        f"got describe error {not_found_code!r}"
    )
    expected_not_found = f"ReplicationGroup {bad_id} not found."
    assert not_found_message == expected_not_found, (
        f"expected message {expected_not_found!r}, got {not_found_message!r}"
    )


def _describe_rg(ec, rg_id: str) -> dict[str, Any]:
    return ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"][0]


def _error(fn):
    """Call fn(); return (code, message) from the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED with {result!r}")


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] in ("ReplicationGroupNotFoundFault",)
            or (exc.response["Error"]["Code"] == "InvalidReplicationGroupState" and "has status deleting" in exc.response["Error"].get("Message", ""))
        ):
            raise


def _poll_until(probe, predicate, timeout_s: float = 600.0, interval_s: float = 15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


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
