"""lakehouse-configuration-server-enforced-policy."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lakehouse-configuration-server-enforced-policy"
GROUP = "server-side"
SERVICES = ["redshift"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyLakehouseConfiguration causes the server to enforce the new lakehouse
    registration state on the cluster; a subsequent, independent DescribeClusters call
    reflects it with no further client action, and reverting round-trips cleanly.
    """
    redshift = ctx.client("redshift")
    cluster_id = ctx.unique_name("sim2real-behav-lh-").lower()

    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    try:
        redshift.create_cluster(
            ClusterIdentifier=cluster_id,
            ClusterType="single-node",
            NodeType="ra3.xlplus",
            MasterUsername="sim2realadmin",
            MasterUserPassword="Sim2Real123!",
            DBName="sim2real",
            PubliclyAccessible=False,
            ClusterSubnetGroupName=subnet_group,
        )
    except Exception as exc:  # noqa: BLE001
        code = _error_code_from_exc(exc)
        if code in {"InsufficientClusterCapacity", "UnsupportedOperation"}:
            raise AssertionError(
                f"could not provision an ra3.xlplus cluster in this account/region "
                f"({code}); lakehouse configuration requires RA3 storage"
            ) from exc
        raise
    ctx.on_cleanup(
        lambda: redshift.delete_cluster(
            ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True
        )
    )
    _wait_cluster_status(ctx, cluster_id, {"available"}, timeout_s=1200, interval_s=2)
    _wait_cluster_availability(ctx, cluster_id, timeout_s=300, interval_s=2)

    baseline = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
    baseline_status = baseline.get("LakehouseRegistrationStatus")

    try:
        _retry_on_invalid_cluster_state(
            lambda: redshift.modify_lakehouse_configuration(
                ClusterIdentifier=cluster_id,
                LakehouseRegistration="Register",
                CatalogName=cluster_id,
            ),
            timeout_s=_budget_s(ctx, 180),
            interval_s=2,
            ctx=ctx,
        )
    except Exception as exc:  # noqa: BLE001
        code = _error_code_from_exc(exc)
        if code in {
            "UnsupportedOperation",
            "DependentServiceAccessDenied",
            "DependentServiceUnavailableFault",
            "InvalidClusterState",
        }:
            raise AssertionError(
                f"ModifyLakehouseConfiguration(Register) was rejected with {code} even "
                "after the cluster settled into 'available'/'Available'; lakehouse "
                "federated-permissions registration needs a pre-existing Glue Data "
                "Catalog + Lake Formation setup this harness cannot provision"
            ) from exc
        raise

    # No further client action beyond the single Modify call: a fresh, independent
    # DescribeClusters must reflect the server-enforced registration.
    registered_status = _poll_until(
        lambda: redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0].get(
            "LakehouseRegistrationStatus"
        ),
        lambda s: s is not None and s != baseline_status,
        timeout_s=_budget_s(ctx, 120),
        interval_s=1,
        ctx=ctx,
    )
    assert registered_status, "LakehouseRegistrationStatus was not populated after Register"
    assert registered_status != baseline_status, (
        f"expected LakehouseRegistrationStatus to change from baseline {baseline_status!r} "
        f"after Register, got {registered_status!r}"
    )

    # Round-trip: Deregister must be enforced the same way. Wait for the cluster to settle
    # back to 'available' (the Register call can leave it transiently 'modifying') before
    # issuing the next mutating call.
    _wait_cluster_status(ctx, cluster_id, {"available"}, timeout_s=300, interval_s=2)
    _wait_cluster_availability(ctx, cluster_id, timeout_s=180, interval_s=2)
    _retry_on_invalid_cluster_state(
        lambda: redshift.modify_lakehouse_configuration(
            ClusterIdentifier=cluster_id,
            LakehouseRegistration="Deregister",
        ),
        timeout_s=_budget_s(ctx, 180),
        interval_s=2,
        ctx=ctx,
    )
    deregistered_status = _poll_until(
        lambda: redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0].get(
            "LakehouseRegistrationStatus"
        ),
        lambda s: s != registered_status,
        timeout_s=_budget_s(ctx, 120),
        interval_s=1,
        ctx=ctx,
    )
    assert deregistered_status != registered_status, (
        f"expected LakehouseRegistrationStatus to change from registered "
        f"{registered_status!r} after Deregister, got {deregistered_status!r}"
    )

    # Settle past the post-Deregister transitional window before returning, the same way the
    # post-Register window is settled above -- otherwise on_cleanup's delete_cluster can race a
    # still-'modifying' cluster and fail with InvalidClusterState.
    _wait_cluster_status(ctx, cluster_id, {"available"}, timeout_s=300, interval_s=2)
    _wait_cluster_availability(ctx, cluster_id, timeout_s=180, interval_s=2)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _error_code_from_exc(exc) -> str | None:
    response = getattr(exc, "response", None)
    if not response:
        return None
    return response.get("Error", {}).get("Code")


def _wait_cluster_status(ctx, cluster_id: str, target_statuses: set[str], *, timeout_s: float, interval_s: float) -> str:
    redshift = ctx.client("redshift")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    status = None
    while time.monotonic() < deadline:
        status = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0][
            "ClusterStatus"
        ]
        if status in target_statuses:
            return status
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_id} {target_statuses}: the run budget ended first; not graded")
    raise AssertionError(f"cluster never reached {target_statuses}, last status={status!r}")


def _wait_cluster_availability(ctx, cluster_id: str, *, timeout_s: float, interval_s: float) -> None:
    """Wait past the brief post-creation window where ClusterAvailabilityStatus can still
    be transitioning (e.g. 'Modifying') even though ClusterStatus already reports
    'available', which otherwise causes a spurious InvalidClusterState on the very next
    mutating call."""
    redshift = ctx.client("redshift")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    availability = None
    while time.monotonic() < deadline:
        cluster = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
        availability = cluster.get("ClusterAvailabilityStatus")
        if availability == "Available":
            return
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_id} availability 'Available': the run budget ended first; not graded")
    raise AssertionError(f"cluster availability never reached 'Available', last={availability!r}")


def _retry_on_invalid_cluster_state(fn, *, timeout_s: float, interval_s: float, ctx=None):
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            if _error_code_from_exc(exc) != "InvalidClusterState":
                raise
            last_exc = exc
            time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("cluster accepting ModifyLakehouseConfiguration: the run budget ended first; not graded") from last_exc
    raise last_exc


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, ctx=None):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    if predicate(value):
        return value
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("polled condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")


def _network_redshift_subnet_group(ctx, client) -> str:
    """A Redshift cluster subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-rsg-")
    client.create_cluster_subnet_group(
        ClusterSubnetGroupName=name,
        Description="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_cluster_subnet_group(ClusterSubnetGroupName=name),
            ("InvalidClusterSubnetGroupStateFault", "ClusterSubnetGroupInUse"),
            ("ClusterSubnetGroupNotFoundFault",),
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
