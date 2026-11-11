"""online-migration-not-found-semantics."""
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
    """Call fn(); return (code, message) from the ClientError it must raise; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

def _assert_error(fn, expected, expected_message):
    """Assert fn() fails with `expected` (Fault/Exception-suffix normalized) and exactly
    `expected_message`; return the code."""
    code, message = _error(fn)
    assert _fault_base(code) == _fault_base(expected), f"expected {expected}, got {code}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    return code

def _wait_rg_status(ec, rg_id, target_statuses, timeout_s=1800.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
        last = groups[0]["Status"]
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"replication group {rg_id} never reached {target_statuses}, last saw {last!r}")

def _delete_rg_tolerant(ec, rg_id):
    try:
        ec.delete_replication_group(ReplicationGroupId=rg_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ReplicationGroupNotFoundFault":
            return
        raise

CHECK = "online-migration-not-found-semantics"
GROUP = 'replication-group'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Start, Test and CompleteMigration on an unknown replication group fail with ReplicationGroupNotFoundFault
    naming it, while on a real group without automatic failover they fail with InvalidParameterValue and their
    own exact messages, so not-found is specific to the id."""
    ec = ctx.client("elasticache")
    endpoints = [{"Address": "10.0.0.10", "Port": 6379}]

    real_id = ctx.unique_name("sim2real-behav-erg-migr-real-")[:40]
    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_replication_group(
        ReplicationGroupId=real_id,
        ReplicationGroupDescription="sim2real online-migration not-found positive control",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=1,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_rg_tolerant(ec, real_id))
    _wait_rg_status(ec, real_id, {"available"})

    # The real group is refused for its own state, never as not-found.
    _assert_error(
        lambda: ec.start_migration(ReplicationGroupId=real_id, CustomerNodeEndpointList=endpoints),
        "InvalidParameterValue",
        "Migration is not supported for auto failover disabled replication group.",
    )
    _assert_error(
        lambda: ec.test_migration(ReplicationGroupId=real_id, CustomerNodeEndpointList=endpoints),
        "InvalidParameterValue",
        "Migration is not supported for auto failover disabled replication group.",
    )
    _assert_error(
        lambda: ec.complete_migration(ReplicationGroupId=real_id),
        "InvalidParameterValue",
        "The replication group must be in migrating state to complete the migration. Please retry later.",
    )

    bogus = ctx.unique_name("sim2real-behav-erg-migr-")
    _assert_error(
        lambda: ec.start_migration(
            ReplicationGroupId=bogus, CustomerNodeEndpointList=endpoints,
        ),
        "ReplicationGroupNotFoundFault",
        f"Replication group '{bogus}' not found.",
    )
    _assert_error(
        lambda: ec.test_migration(
            ReplicationGroupId=bogus, CustomerNodeEndpointList=endpoints,
        ),
        "ReplicationGroupNotFoundFault",
        f"Replication group '{bogus}' not found.",
    )
    _assert_error(
        lambda: ec.complete_migration(ReplicationGroupId=bogus),
        "ReplicationGroupNotFoundFault",
        f"Replication group '{bogus}' not found",
    )


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
