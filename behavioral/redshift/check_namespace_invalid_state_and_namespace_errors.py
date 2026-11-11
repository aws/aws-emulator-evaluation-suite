"""namespace-invalid-state-and-namespace-errors."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "namespace-invalid-state-and-namespace-errors"
GROUP = "error-semantics"
SERVICES = ["redshift"]

MSG_NOT_FOUND = "Cluster {cluster_id} can't be found."
MSG_NOT_READY = (
    "This cluster version doesn't support Register Namespace operation. "
    "Please upgrade to the latest cluster version."
)
MSG_IN_TRANSITION = "Cluster {cluster_id} is not in available state."

# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
_NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterNamespace is rejected with ClusterNotFound for a nonexistent cluster and with
    InvalidParameterValue for a cluster still initializing, then succeeds once it is available;
    DeregisterNamespace on an available cluster succeeds whether or not the consumer was registered."""
    redshift = ctx.client("redshift")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # 1. Nonexistent cluster -> ClusterNotFound (no real cluster required).
    missing_cluster_id = ctx.unique_name("sim2real-behav-nsmiss-")
    code, message = _refusal(
        lambda: redshift.register_namespace(
            NamespaceIdentifier={"ProvisionedIdentifier": {"ClusterIdentifier": missing_cluster_id}},
            ConsumerIdentifiers=[account_id],
        )
    )
    assert code == "ClusterNotFound", f"expected ClusterNotFound, got {code}"
    expected = MSG_NOT_FOUND.format(cluster_id=missing_cluster_id)
    assert message == expected, f"expected {expected!r}, got {message!r}"

    subnet_group = _network_redshift_subnet_group(ctx, redshift)

    # 2. Cluster exists but hasn't finished initializing -> RegisterNamespace is rejected
    #    with InvalidParameterValue, its message naming Register Namespace specifically
    #    (not ClusterNotFound, and not a bare request-shape validation error). A ClusterStatus
    #    read after the call proves it landed while the cluster was still initializing.
    cluster_id, precondition_code, precondition_message = _register_while_initializing(
        ctx, redshift, subnet_group, account_id
    )
    assert precondition_code == "InvalidParameterValue", (
        f"expected InvalidParameterValue, got {precondition_code}: {precondition_message}"
    )
    assert precondition_message == MSG_NOT_READY, (
        f"expected {MSG_NOT_READY!r}, got {precondition_message!r}"
    )

    _wait_cluster_available(redshift, cluster_id)

    # 3. Available but never registered -> DeregisterNamespace still succeeds: real AWS
    #    treats it as an idempotent "ensure absent" rather than a precondition check.
    resp = redshift.deregister_namespace(
        NamespaceIdentifier={"ProvisionedIdentifier": {"ClusterIdentifier": cluster_id}},
        ConsumerIdentifiers=[account_id],
    )
    assert resp["Status"] == "Deregistering", f"expected Deregistering, got {resp['Status']}"
    _wait_cluster_available(redshift, cluster_id)

    # Positive control: RegisterNamespace succeeds once the cluster really is available.
    # Independent consequence read: RegisterNamespace exposes no dedicated describe call,
    # so proof that it did real server-side work -- rather than just echoing the request --
    # comes from an immediate follow-up mutation on the identical cluster independently
    # observing it still mid-transition, before the async work settles back to 'available'.
    code, message = _deregister_while_register_applies(redshift, cluster_id, account_id)
    assert code == "InvalidClusterState", (
        f"expected the immediately-following call to independently observe the cluster "
        f"still mid-transition (InvalidClusterState), got {code}"
    )
    expected = MSG_IN_TRANSITION.format(cluster_id=cluster_id)
    assert message == expected, f"expected {expected!r}, got {message!r}"


# ===== helpers =====
#: Fresh clusters tried for a RegisterNamespace that lands while the cluster is still initializing.
_INITIALIZING_WINDOW_ATTEMPTS = 3
#: Register-then-deregister pairs tried for a DeregisterNamespace that lands while the register applies.
_APPLY_WINDOW_ATTEMPTS = 3


def _register_while_initializing(ctx, redshift, subnet_group, account_id):
    """Create a cluster and call RegisterNamespace on it at once; return ``(cluster_id, code,
    message)`` of the refusal once a ClusterStatus read after the call shows the cluster still not
    'available'. A register accepted on a cluster still initializing fails the check; a cluster
    that reached 'available' first is set aside for a fresh one, up to the attempt cap."""
    statuses = []
    for _ in range(_INITIALIZING_WINDOW_ATTEMPTS):
        cluster_id = _create_cluster(ctx, redshift, subnet_group, account_id)
        try:
            result = redshift.register_namespace(
                NamespaceIdentifier={"ProvisionedIdentifier": {"ClusterIdentifier": cluster_id}},
                ConsumerIdentifiers=[account_id],
            )
            code = message = None
        except ClientError as exc:
            result = None
            code, message = exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
        status = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]["ClusterStatus"]
        statuses.append(status)
        if status != "available":
            assert result is None, (
                f"RegisterNamespace unexpectedly succeeded against a still-initializing cluster "
                f"({status!r}): {result!r}"
            )
            return cluster_id, code, message
    raise AssertionError(
        f"every new cluster read 'available' right after the register call, so none was still "
        f"initializing when it landed; statuses read: {statuses}"
    )


def _deregister_while_register_applies(redshift, cluster_id: str, account_id: str):
    """RegisterNamespace on the available cluster (answering 'Registering'), then DeregisterNamespace
    at once; return the deregister's refusal ``(code, message)``. A deregister accepted is followed
    by a ClusterStatus read: 'modifying' fails the check, since the cluster accepted it while the
    register applied; any other status means the register had already applied, so the cluster
    settles and the pair runs again, up to the cap."""
    namespace_id = {"ProvisionedIdentifier": {"ClusterIdentifier": cluster_id}}
    accepted = []
    for _ in range(_APPLY_WINDOW_ATTEMPTS):
        resp = redshift.register_namespace(
            NamespaceIdentifier=namespace_id, ConsumerIdentifiers=[account_id]
        )
        assert resp["Status"] == "Registering", f"expected Registering, got {resp['Status']}"
        try:
            dereg = redshift.deregister_namespace(
                NamespaceIdentifier=namespace_id, ConsumerIdentifiers=[account_id]
            )
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        status = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]["ClusterStatus"]
        assert status != "modifying", (
            f"DeregisterNamespace was accepted ({dereg['Status']!r}) right after RegisterNamespace "
            f"while the cluster still reads 'modifying'"
        )
        accepted.append(dereg["Status"])
        _wait_cluster_available(redshift, cluster_id)
    raise AssertionError(
        f"DeregisterNamespace issued right after RegisterNamespace was accepted every time "
        f"({accepted}), so it never observed the register still applying"
    )


def _create_cluster(ctx, redshift, subnet_group: str, account_id: str) -> str:
    """A new single-node cluster, returned at once without waiting for it; teardown waits for
    'available', deregisters the namespace and deletes the cluster."""
    cluster_id = ctx.unique_name("sim2real-behav-ns-")
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType=_orderable_node_type(redshift),
        ClusterType="single-node",
        MasterUsername="s2radmin",
        MasterUserPassword="Sim2Real-Passw0rd1",
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
        ClusterSubnetGroupName=subnet_group,
    )

    def _cleanup() -> None:
        try:
            _wait_cluster_available(redshift, cluster_id)
        except AssertionError:
            pass
        try:
            redshift.deregister_namespace(
                NamespaceIdentifier={"ProvisionedIdentifier": {"ClusterIdentifier": cluster_id}},
                ConsumerIdentifiers=[account_id],
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFound":
                raise
        _delete_cluster_retrying(redshift, cluster_id)

    ctx.on_cleanup(_cleanup)
    return cluster_id


def _refusal(fn):
    """Call *fn*, which must be refused; return the AWS error ``(code, message)``.

    A call that succeeds raises ``AssertionError``: the refusal is the claim."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _delete_cluster_retrying(redshift, cluster_id: str, timeout_s: float = 780.0) -> None:
    """DeleteCluster, retried while the cluster is mid-modification (InvalidClusterState);
    any other refusal raises so a leak is reported, not swallowed."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFound":
                return
            if code != "InvalidClusterState" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _orderable_node_type(redshift, cluster_type: str = "single-node") -> str:
    """Node type availability is account/region-specific (dc2 vs ra3 opt-in), so a
    hardcoded literal can be rejected with InvalidParameterValue on an account that never
    ordered it -- discover what this account can actually order instead."""
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
    chosen = next((nt for nt in _NODE_TYPE_PREFERENCE if nt in available), None)
    if chosen is None:
        if not available:
            raise AssertionError(f"no orderable {cluster_type!r} node types in this account/region")
        chosen = sorted(available)[0]
    return chosen


def _wait_cluster_available(redshift, cluster_id: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]["ClusterStatus"]
        if status == "available":
            return
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} did not become available within {timeout_s}s")


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
