"""namespace-register-wrong-state-blocked."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "namespace-register-wrong-state-blocked"
GROUP = "overly-permissive"
SERVICES = ["redshift"]

MSG_NOT_READY = (
    "This cluster version doesn't support Register Namespace operation. "
    "Please upgrade to the latest cluster version."
)

NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterNamespace on a cluster that is not yet available is rejected with InvalidParameterValue
    and its exact message; once the cluster settles the identical call answers 'Registering' and
    DeregisterNamespace then answers 'Deregistering'."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    redshift = ctx.client("redshift")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    consumers = [account_id]

    # A cluster that was *just* created is still provisioning; RegisterNamespace against a
    # cluster whose own namespace isn't addressable yet is rejected. A ClusterStatus read after
    # the call proves it landed inside that window; a cluster that settled first is replaced.
    cluster_id, code, message = _register_while_creating(
        ctx, redshift, subnet_group, consumers, teardown_deadline
    )
    namespace_id = {"ProvisionedIdentifier": {"ClusterIdentifier": cluster_id}}
    assert code == "InvalidParameterValue", (
        f"expected InvalidParameterValue while the cluster is still creating, got {code!r}"
    )
    assert message == MSG_NOT_READY, f"expected {MSG_NOT_READY!r}, got {message!r}"

    _wait_for_cluster_status(ctx, cluster_id, {"available"}, timeout_s=900)
    ctx.on_cleanup(
        lambda: _best_effort(
            ctx,
            lambda: redshift.deregister_namespace(
                NamespaceIdentifier=namespace_id, ConsumerIdentifiers=consumers
            ),
            teardown_deadline,
        )
    )

    # Positive control: once the cluster is genuinely available, RegisterNamespace
    # succeeds. Retry through InvalidClusterState only -- ClusterStatus flips to
    # 'available' slightly before the cluster's internal availability settles, and a
    # register attempted in that gap is rejected too.
    result = _retry_through_invalid_state(
        lambda: redshift.register_namespace(
            NamespaceIdentifier=namespace_id, ConsumerIdentifiers=consumers
        ),
        timeout_s=180,
    )
    assert result["Status"] == "Registering", f"expected Registering, got {result['Status']!r}"

    # Independent terminal read, at a different operation: DeregisterNamespace against
    # the namespace this check just registered succeeds. (Redshift has no dedicated
    # "describe this registration" call, and the cluster's own
    # LakehouseRegistrationStatus/CatalogArn fields do not reflect RegisterNamespace's
    # effect -- so this lifecycle call is the
    # strongest terminal signal available.)
    deregister_result = _retry_through_invalid_state(
        lambda: redshift.deregister_namespace(
            NamespaceIdentifier=namespace_id, ConsumerIdentifiers=consumers
        ),
        timeout_s=180,
    )
    assert deregister_result["Status"] == "Deregistering", (
        f"expected Deregistering, got {deregister_result['Status']!r}"
    )


#: Fresh clusters tried for a RegisterNamespace that lands while the cluster is still creating.
_CREATING_WINDOW_ATTEMPTS = 3


def _register_while_creating(ctx, redshift, subnet_group, consumers, teardown_deadline):
    """Create a cluster and call RegisterNamespace on it at once; return ``(cluster_id, code,
    message)`` of the refusal once a ClusterStatus read after the call shows the cluster still not
    'available'. A register accepted on a cluster still creating fails the check; a cluster that
    reached 'available' first is set aside for a fresh one, up to the attempt cap."""
    statuses = []
    for _ in range(_CREATING_WINDOW_ATTEMPTS):
        cluster_id = ctx.unique_name("sim2real-nsreg-cl-")
        redshift.create_cluster(
            ClusterIdentifier=cluster_id,
            NodeType=_node_type(redshift),
            MasterUsername="sim2realadmin",
            MasterUserPassword="Sim2RealTest1234!",
            ClusterType="single-node",
            PubliclyAccessible=False,
            # Encrypted at rest, as a customer would configure it; RA3 node types refuse retention 0.
            Encrypted=True,
            AutomatedSnapshotRetentionPeriod=1,
            Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
            ClusterSubnetGroupName=subnet_group,
        )
        ctx.on_cleanup(lambda c=cluster_id: _delete_cluster(ctx, c, teardown_deadline))
        namespace_id = {"ProvisionedIdentifier": {"ClusterIdentifier": cluster_id}}
        try:
            result = redshift.register_namespace(
                NamespaceIdentifier=namespace_id, ConsumerIdentifiers=consumers
            )
            code = message = None
        except ClientError as err:
            result = None
            code, message = err.response["Error"]["Code"], err.response["Error"].get("Message")
        status = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0][
            "ClusterStatus"
        ]
        statuses.append(status)
        if status != "available":
            assert result is None, (
                f"RegisterNamespace was accepted on a cluster still {status!r}: {result!r}"
            )
            return cluster_id, code, message
    raise AssertionError(
        f"every new cluster read 'available' right after the register call, so none was still "
        f"creating when it landed; statuses read: {statuses}"
    )


def _node_type(rs, cluster_type: str = "single-node") -> str:
    """Cheapest orderable node type for *cluster_type* in this region/account."""
    available = []
    marker = None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = rs.describe_orderable_cluster_options(**kwargs)
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


def _retry_through_invalid_state(fn, timeout_s: float):
    """Retry *fn* while it raises InvalidClusterState; re-raise any other error."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidClusterState" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


# budget.cleanup_timeout for behavioral/redshift, one deadline shared by every teardown of a run.
_TEARDOWN_RETRY_S = 1800.0


def _teardown_deadline(teardown_deadline) -> float:
    """The one deadline this run's teardowns share, started by the first to ask, with a margin
    inside the budget so a teardown raises its own error before the runner gives up."""
    return teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 120.0)


def _best_effort(ctx, fn, teardown_deadline) -> bool:
    """Teardown: retry InvalidClusterState (the cluster is still modifying after a namespace
    (de)registration) every 2 s to the shared cleanup deadline; True when ClusterNotFound."""
    deadline = _teardown_deadline(teardown_deadline)
    while True:
        try:
            fn()
            return False
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFound":
                return True
            if code != "InvalidClusterState" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _wait_for_cluster_status(ctx, cluster_id: str, targets: set, timeout_s: float) -> None:
    redshift = ctx.client("redshift")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
        if cluster["ClusterStatus"] in targets:
            return
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_id} never reached {targets} within {timeout_s}s")


def _delete_cluster(ctx, cluster_id: str, teardown_deadline) -> None:
    """Wait for available, delete, and wait for the cluster to be gone, all within the shared
    cleanup deadline."""
    redshift = ctx.client("redshift")
    deadline = _teardown_deadline(teardown_deadline)
    try:
        _wait_for_cluster_status(ctx, cluster_id, {"available"}, timeout_s=max(0.0, deadline - time.monotonic()))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFound":
            raise
    if _best_effort(
        ctx,
        lambda: redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True),
        teardown_deadline,
    ):
        return
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
