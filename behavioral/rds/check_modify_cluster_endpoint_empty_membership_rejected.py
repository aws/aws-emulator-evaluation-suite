"""modify-cluster-endpoint-empty-membership-rejected."""
from __future__ import annotations

import random
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-cluster-endpoint-empty-membership-rejected"
GROUP = "overly-permissive"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyDBClusterEndpoint with both StaticMembers and ExcludedMembers populated is rejected and
    leaves the custom endpoint's membership unchanged; a valid modification is then accepted."""
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-rds-clus-")
    instance_id = ctx.unique_name("sim2real-rds-cinst-")
    endpoint_id = ctx.unique_name("sim2real-rds-ep-")
    password = _rds_password()

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-postgresql",
        MasterUsername="sim2real",
        MasterUserPassword=password,
        BackupRetentionPeriod=1,
        ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 2.0},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cluster(rds, cluster_id))

    _wait_for_cluster_status(rds, cluster_id, {"available"}, timeout_s=_budget_s(ctx, 900), interval_s=2, ctx=ctx)

    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBInstanceClass="db.serverless",
        Engine="aurora-postgresql",
        DBClusterIdentifier=cluster_id,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, instance_id))

    _wait_for_instance_status(rds, instance_id, {"available"}, timeout_s=_budget_s(ctx, 900), interval_s=2, ctx=ctx)

    rds.create_db_cluster_endpoint(
        DBClusterIdentifier=cluster_id,
        DBClusterEndpointIdentifier=endpoint_id,
        EndpointType="ANY",
        StaticMembers=[instance_id],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster_endpoint(DBClusterEndpointIdentifier=endpoint_id)
    )
    _wait_for_endpoint_status(rds, endpoint_id, {"available"}, timeout_s=_budget_s(ctx, 300), interval_s=2, ctx=ctx)

    original = rds.describe_db_cluster_endpoints(DBClusterEndpointIdentifier=endpoint_id)[
        "DBClusterEndpoints"
    ][0]
    assert original["StaticMembers"] == [instance_id], (
        f"expected StaticMembers=[{instance_id!r}] right after creation, got {original['StaticMembers']!r}"
    )

    # A custom endpoint can hold only one of the two list types; supply both at once.
    err = _client_error(
        lambda: rds.modify_db_cluster_endpoint(
            DBClusterEndpointIdentifier=endpoint_id,
            StaticMembers=[instance_id],
            ExcludedMembers=[instance_id],
        )
    )
    assert err.get("Code") == "InvalidParameterValue", (
        f"expected InvalidParameterValue, got {err.get('Code')}"
    )
    expected = "You can't specify both static and excluded members"
    assert err.get("Message") == expected, f"expected message {expected!r}, got {err.get('Message')!r}"

    # effect absent: membership definition unchanged
    unchanged = rds.describe_db_cluster_endpoints(DBClusterEndpointIdentifier=endpoint_id)[
        "DBClusterEndpoints"
    ][0]
    assert unchanged["StaticMembers"] == [instance_id], (
        f"rejected ModifyDBClusterEndpoint should leave StaticMembers=[{instance_id!r}] "
        f"unchanged, got {unchanged['StaticMembers']!r}"
    )
    assert unchanged.get("ExcludedMembers", []) == [], (
        f"rejected ModifyDBClusterEndpoint should not have set ExcludedMembers, "
        f"got {unchanged.get('ExcludedMembers')!r}"
    )

    # --- positive control: a valid, distinct modification is accepted ---
    rds.modify_db_cluster_endpoint(DBClusterEndpointIdentifier=endpoint_id, EndpointType="READER")
    updated = _poll_until(
        lambda: rds.describe_db_cluster_endpoints(DBClusterEndpointIdentifier=endpoint_id)[
            "DBClusterEndpoints"
        ][0],
        lambda e: e["CustomEndpointType"].upper() == "READER" and e["Status"] in ("available", "modifying"),
        timeout_s=_budget_s(ctx, 180),
        interval_s=2,
        ctx=ctx,
    )
    assert updated["CustomEndpointType"].upper() == "READER", (
        f"expected the distinct, valid modification (EndpointType=READER) to be accepted, "
        f"got CustomEndpointType={updated['CustomEndpointType']!r}"
    )


def _rds_password() -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=24)) + "9Aa"


def _client_error(fn) -> dict:
    """The botocore Error dict fn() raised. An unexpected SUCCESS raises, because a target
    accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=900.0, interval_s=2.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("polled condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s:.0f}s (last={last!r})")


def _wait_for_cluster_status(rds, cluster_id, target_statuses, *, timeout_s=900.0, interval_s=2.0, ctx=None):
    def _probe():
        return rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]

    return _poll_until(_probe, lambda c: c["Status"] in target_statuses, timeout_s=timeout_s, interval_s=interval_s, ctx=ctx)


def _wait_for_instance_status(rds, instance_id, target_statuses, *, timeout_s=900.0, interval_s=2.0, ctx=None):
    def _probe():
        return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]

    return _poll_until(
        _probe, lambda i: i["DBInstanceStatus"] in target_statuses, timeout_s=timeout_s, interval_s=interval_s, ctx=ctx
    )


def _wait_for_endpoint_status(rds, endpoint_id, target_statuses, *, timeout_s=300.0, interval_s=2.0, ctx=None):
    def _probe():
        return rds.describe_db_cluster_endpoints(DBClusterEndpointIdentifier=endpoint_id)[
            "DBClusterEndpoints"
        ][0]

    return _poll_until(_probe, lambda e: e["Status"] in target_statuses, timeout_s=timeout_s, interval_s=interval_s, ctx=ctx)


def _delete_instance(rds, instance_id) -> None:
    try:
        _wait_for_instance_status(rds, instance_id, {"available"}, timeout_s=900, interval_s=2)
    except rds.exceptions.DBInstanceNotFoundFault:
        return
    except AssertionError:
        pass  # not settled: the delete below still runs and raises if it is refused
    try:
        rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    except rds.exceptions.DBInstanceNotFoundFault:
        return
    except ClientError as exc:
        raise RuntimeError(f"db instance {instance_id} was not deleted: {exc!r}") from exc
    _wait_for_instance_gone(rds, instance_id, timeout_s=900, interval_s=2)


def _wait_for_instance_gone(rds, instance_id, *, timeout_s=900.0, interval_s=2.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_instances(DBInstanceIdentifier=instance_id)
        except rds.exceptions.DBInstanceNotFoundFault:
            return
        time.sleep(interval_s)
    raise RuntimeError(f"db instance {instance_id} was not deleted: still listed after {timeout_s:.0f}s")


def _delete_cluster(rds, cluster_id) -> None:
    try:
        _wait_for_cluster_status(rds, cluster_id, {"available"}, timeout_s=900, interval_s=2)
    except rds.exceptions.DBClusterNotFoundFault:
        return
    except AssertionError:
        pass  # not settled: the delete below still runs and raises if it is refused
    try:
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    except rds.exceptions.DBClusterNotFoundFault:
        return
    except ClientError as exc:
        raise RuntimeError(f"db cluster {cluster_id} was not deleted: {exc!r}") from exc


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
