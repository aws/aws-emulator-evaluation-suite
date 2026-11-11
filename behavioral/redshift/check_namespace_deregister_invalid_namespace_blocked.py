"""namespace-deregister-invalid-namespace-blocked."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "namespace-deregister-invalid-namespace-blocked"
GROUP = "overly-permissive"
SERVICES = ["redshift"]

# Node type availability (e.g. dc2.large) varies by account entitlement; discover
# what this account can actually order rather than hardcoding one (see _node_type).
NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeregisterNamespace on a never-created cluster is rejected with ClusterNotFound and its exact
    message, while on an available cluster whose namespace was never registered it answers
    "Deregistering", and register, deregister and a repeated deregister then all succeed."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    redshift = ctx.client("redshift")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # Existence is enforced: a cluster identifier that was never created is
    # rejected outright, regardless of registration state.
    missing_cluster_id = ctx.unique_name("sim2real-nsdereg-nocl-")
    missing_code, missing_message = _refusal(
        lambda: redshift.deregister_namespace(
            NamespaceIdentifier={"ProvisionedIdentifier": {"ClusterIdentifier": missing_cluster_id}},
            ConsumerIdentifiers=[account_id],
        )
    )
    assert missing_code == "ClusterNotFound", f"expected ClusterNotFound, got {missing_code}"
    expected_message = f"Cluster {missing_cluster_id} can't be found."
    assert missing_message == expected_message, (
        f"expected {expected_message!r}, got {missing_message!r}"
    )

    cluster_id = _create_available_cluster(ctx, teardown_deadline)
    namespace_id = {"ProvisionedIdentifier": {"ClusterIdentifier": cluster_id}}
    consumers = [account_id]

    # Prior registration state is NOT enforced: the cluster is available but was
    # never registered, and DeregisterNamespace still succeeds -- an idempotent
    # no-op rather than InvalidNamespaceFault.
    first_deregister = redshift.deregister_namespace(
        NamespaceIdentifier=namespace_id, ConsumerIdentifiers=consumers
    )
    assert first_deregister["Status"] == "Deregistering", (
        f"expected Deregistering, got {first_deregister['Status']}"
    )

    # Independent read at the destination: DeregisterNamespace drives the
    # cluster itself through a real, bounded "modifying" transition -- assert
    # the recovery, not a same-instant snapshot that would race it.
    _wait_for_cluster_status(ctx, cluster_id, {"available"}, timeout_s=300)

    # Consequence: registering afterwards still works normally, proving the
    # earlier no-op left no stuck or corrupted state behind.
    register_result = redshift.register_namespace(
        NamespaceIdentifier=namespace_id, ConsumerIdentifiers=consumers
    )
    assert register_result["Status"] == "Registering", (
        f"expected Registering, got {register_result['Status']}"
    )
    _wait_for_cluster_status(ctx, cluster_id, {"available"}, timeout_s=300)

    deregister_result = redshift.deregister_namespace(
        NamespaceIdentifier=namespace_id, ConsumerIdentifiers=consumers
    )
    assert deregister_result["Status"] == "Deregistering", (
        f"expected Deregistering, got {deregister_result['Status']}"
    )
    _wait_for_cluster_status(ctx, cluster_id, {"available"}, timeout_s=300)

    # Consequence, not just the mutating call's own response: deregistering the
    # already-deregistered namespace a second time succeeds the same idempotent
    # way as the very first call did -- closing the loop and confirming the
    # no-op behavior is symmetric, not a one-time fluke of the unregistered case.
    repeat_deregister = redshift.deregister_namespace(
        NamespaceIdentifier=namespace_id, ConsumerIdentifiers=consumers
    )
    assert repeat_deregister["Status"] == "Deregistering", (
        f"expected a second DeregisterNamespace to remain idempotent, got {repeat_deregister['Status']}"
    )


def _refusal(fn):
    """Call *fn*, which must be refused; return the AWS error ``(code, message)``."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _node_type(redshift, cluster_type: str = "single-node") -> str:
    """A node type this account can actually order for *cluster_type* right now."""
    available: list[str] = []
    marker = None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = redshift.describe_orderable_cluster_options(**kwargs)
        for opt in resp.get("OrderableClusterOptions", []):
            if opt.get("ClusterType") != cluster_type:
                continue
            nt = opt.get("NodeType")
            if nt and nt not in available:
                available.append(nt)
        marker = resp.get("Marker")
        if not marker:
            break
    chosen = next((nt for nt in NODE_TYPE_PREFERENCE if nt in available), None)
    if chosen is None:
        if not available:
            raise AssertionError(f"no orderable {cluster_type} options in this region")
        chosen = sorted(available)[0]
    return chosen


def _create_available_cluster(ctx, teardown_deadline) -> str:
    redshift = ctx.client("redshift")
    cluster_id = ctx.unique_name("sim2real-nsdereg-cl-")
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType=_node_type(redshift),
        MasterUsername="sim2realadmin",
        ManageMasterPassword=True,
        ClusterType="single-node",
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-behavioral", "Value": CHECK}],
        ClusterSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cluster(ctx, cluster_id, teardown_deadline))
    _wait_for_cluster_status(ctx, cluster_id, {"available"}, timeout_s=900)
    return cluster_id


def _wait_for_cluster_status(ctx, cluster_id: str, targets: set, timeout_s: float) -> None:
    redshift = ctx.client("redshift")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
        if cluster["ClusterStatus"] in targets:
            return
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_id} never reached {targets} within {timeout_s}s")


# budget.cleanup_timeout for behavioral/redshift, one deadline shared by every teardown of a run.
_TEARDOWN_RETRY_S = 1800.0


def _teardown_deadline(teardown_deadline) -> float:
    """The one deadline this run's teardowns share, started by the first to ask, with a margin
    inside the budget so a teardown raises its own error before the runner gives up."""
    return teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 120.0)


def _delete_cluster(ctx, cluster_id: str, teardown_deadline) -> None:
    """A namespace (de)registration keeps an operation running on an available cluster for a
    while; retry DeleteCluster on InvalidClusterState every 2 s, and wait for it to be gone, all
    within the shared cleanup deadline."""
    redshift = ctx.client("redshift")
    deadline = _teardown_deadline(teardown_deadline)
    try:
        _wait_for_cluster_status(
            ctx, cluster_id, {"available"}, timeout_s=max(0.0, deadline - time.monotonic())
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFound":
            raise
    while True:
        try:
            redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFound":
                return
            if code != "InvalidClusterState" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while time.monotonic() < deadline:
        try:
            redshift.describe_clusters(ClusterIdentifier=cluster_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ClusterNotFound":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_id} still exists at the cleanup deadline")


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
