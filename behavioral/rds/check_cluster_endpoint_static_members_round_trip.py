"""cluster-endpoint-static-members-round-trip."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-endpoint-static-members-round-trip"
GROUP = "representation"
SERVICES = ["rds"]

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-epmembers"},
]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StaticMembers supplied to CreateDBClusterEndpoint is preserved exactly on
    DescribeDBClusterEndpoints, and stays exactly as configured even after an unrelated
    cluster membership change (a second instance joining the same cluster)."""
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-epmembers-")
    password = _rand_password()

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        DeletionProtection=False,
        Tags=_MANAGED_TAGS,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    )
    _wait_cluster_status(ctx, cluster_id, "available", timeout_s=900)

    instance1_id = ctx.unique_name("sim2real-epm1-")
    rds.create_db_instance(
        DBInstanceIdentifier=instance1_id,
        Engine="aurora-mysql",
        DBInstanceClass="db.t3.medium",
        DBClusterIdentifier=cluster_id,
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=instance1_id, SkipFinalSnapshot=True)
    )
    _wait_instance_status(ctx, instance1_id, "available", timeout_s=1200)

    endpoint_id = ctx.unique_name("sim2real-ep-")
    rds.create_db_cluster_endpoint(
        DBClusterIdentifier=cluster_id,
        DBClusterEndpointIdentifier=endpoint_id,
        EndpointType="ANY",
        StaticMembers=[instance1_id],
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: rds.delete_db_cluster_endpoint(DBClusterEndpointIdentifier=endpoint_id))
    endpoint = _wait_endpoint_status(ctx, endpoint_id, "available", timeout_s=300)
    assert endpoint["StaticMembers"] == [instance1_id], (
        f"expected StaticMembers == [{instance1_id!r}] right after creation, got {endpoint['StaticMembers']!r}"
    )

    # Unrelated cluster membership change: a second instance joins the same cluster.
    instance2_id = ctx.unique_name("sim2real-epm2-")
    rds.create_db_instance(
        DBInstanceIdentifier=instance2_id,
        Engine="aurora-mysql",
        DBInstanceClass="db.t3.medium",
        DBClusterIdentifier=cluster_id,
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=instance2_id, SkipFinalSnapshot=True)
    )

    # The new member shows up on the cluster...
    _wait_cluster_member_count(ctx, cluster_id, 2, timeout_s=300)
    # ...but the endpoint's StaticMembers is untouched by the membership change.
    reread = rds.describe_db_cluster_endpoints(DBClusterEndpointIdentifier=endpoint_id)[
        "DBClusterEndpoints"
    ][0]
    assert reread["StaticMembers"] == [instance1_id], (
        f"StaticMembers changed after unrelated membership change: {reread['StaticMembers']!r}"
    )

    # Bring instance2 to "available" here, in the body, rather than in its cleanup: DeleteDBInstance
    # is rejected while an instance is still "creating", and ctx.on_cleanup's teardown budget (60s)
    # is far shorter than the several minutes RDS instance creation legitimately takes -- waiting for
    # that transition inside the cleanup callback starves every cleanup queued behind it.
    _wait_instance_status(ctx, instance2_id, "available", timeout_s=1200)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _wait_cluster_status(ctx, cluster_id, target_status, timeout_s=900, poll_s=2) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if last["Status"] == target_status:
            return last
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_id} {target_status!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"cluster {cluster_id} never reached {target_status!r}, last status {last and last['Status']!r}"
    )


def _wait_instance_status(ctx, instance_id, target_status, timeout_s=1200, poll_s=2) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        if last["DBInstanceStatus"] == target_status and not last.get("PendingModifiedValues"):
            return last
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"instance {instance_id} {target_status!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"instance {instance_id} never reached {target_status!r}, "
        f"last status {last and last['DBInstanceStatus']!r}"
    )


def _wait_endpoint_status(ctx, endpoint_id, target_status, timeout_s=300, poll_s=2) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        matches = rds.describe_db_cluster_endpoints(DBClusterEndpointIdentifier=endpoint_id)[
            "DBClusterEndpoints"
        ]
        last = matches[0] if matches else None
        if last is not None and last["Status"] == target_status:
            return last
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"endpoint {endpoint_id} {target_status!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"endpoint {endpoint_id} never reached {target_status!r}, last observed {last!r}"
    )


def _wait_cluster_member_count(ctx, cluster_id, target_count, timeout_s=300, poll_s=2) -> None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = 0
    while time.monotonic() < deadline:
        cluster = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        last = len(cluster.get("DBClusterMembers", []))
        if last >= target_count:
            return
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_id} member count {target_count}: the run budget ended first; not graded")
    raise AssertionError(
        f"cluster {cluster_id} member count never reached {target_count}, last observed {last}"
    )


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=2.0):
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
