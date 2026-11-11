"""deregister-namespace-unregistered-accepted-nonexistent-cluster-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-namespace-unregistered-accepted-nonexistent-cluster-rejected"
GROUP = "error-semantics"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeregisterNamespace against a nonexistent cluster is rejected with ClusterNotFound, while on an
    available cluster DeregisterNamespace and RegisterNamespace are accepted in either order whatever
    the prior registration state, and the cluster stays 'available' throughout."""
    redshift = ctx.client("redshift")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    nonexistent_cluster_id = ctx.unique_name("sim2real-noclust-")
    missing_cluster_code, missing_cluster_message = _error_code(
        lambda: redshift.deregister_namespace(
            NamespaceIdentifier={"ProvisionedIdentifier": {"ClusterIdentifier": nonexistent_cluster_id}},
            ConsumerIdentifiers=[account_id],
        )
    )
    assert missing_cluster_code == "ClusterNotFound", (
        f"expected ClusterNotFound for a nonexistent cluster, got {missing_cluster_code!r}"
    )
    assert missing_cluster_message == f"Cluster {nonexistent_cluster_id} can't be found.", missing_cluster_message

    cluster_id = ctx.unique_name("sim2real-deregns-")
    # One deadline for every teardown of the run, started by the first one that runs.
    teardown_deadline: dict = {}
    subnet_group = _network_redshift_subnet_group(ctx, redshift, teardown_deadline)
    ctx.on_cleanup(lambda: _delete_cluster(redshift, cluster_id, teardown_deadline))
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType="ra3.xlplus",
        MasterUsername="sim2realadmin",
        MasterUserPassword="Sim2RealTest1234!",
        ClusterType="single-node",
        DBName="dev",
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        ClusterSubnetGroupName=subnet_group,
    )
    _wait_for_status(ctx, redshift, cluster_id, "available", timeout_s=900)

    def _namespace_ident():
        return {"ProvisionedIdentifier": {"ClusterIdentifier": cluster_id}}

    # A namespace that was never registered is still accepted by DeregisterNamespace for a
    # self-consumer identifier -- no InvalidNamespaceFault, no state precondition at all.
    dereg_never_registered = _when_idle(
        lambda: redshift.deregister_namespace(NamespaceIdentifier=_namespace_ident(), ConsumerIdentifiers=[account_id])
    )
    assert dereg_never_registered["Status"] == "Deregistering", (
        f"expected Deregistering even though this namespace was never registered, "
        f"got {dereg_never_registered['Status']!r}"
    )

    # Repeating the SAME call again, still never having registered, gives the identical result --
    # not a one-off fluke and not a hidden state gate that only opens once.
    _wait_for_status(ctx, redshift, cluster_id, "available", timeout_s=180)
    dereg_repeat = _when_idle(
        lambda: redshift.deregister_namespace(NamespaceIdentifier=_namespace_ident(), ConsumerIdentifiers=[account_id])
    )
    assert dereg_repeat["Status"] == "Deregistering", (
        f"expected the repeat DeregisterNamespace to be identically accepted, "
        f"got {dereg_repeat['Status']!r}"
    )

    # RegisterNamespace and DeregisterNamespace toggle freely from either side.
    _wait_for_status(ctx, redshift, cluster_id, "available", timeout_s=180)
    reg = _when_idle(
        lambda: redshift.register_namespace(NamespaceIdentifier=_namespace_ident(), ConsumerIdentifiers=[account_id])
    )
    assert reg["Status"] == "Registering", f"expected Registering, got {reg['Status']!r}"

    _wait_for_status(ctx, redshift, cluster_id, "available", timeout_s=180)
    dereg = _when_idle(
        lambda: redshift.deregister_namespace(NamespaceIdentifier=_namespace_ident(), ConsumerIdentifiers=[account_id])
    )
    assert dereg["Status"] == "Deregistering", f"expected Deregistering, got {dereg['Status']!r}"

    # Independent terminal read at a different operation: none of the above namespace churn left
    # the cluster itself anywhere but back at a healthy, available state -- each register/
    # deregister call kicks the cluster through a brief transient status, so this is a bounded
    # wait for that settle, not a poll for the namespace state itself.
    final = _wait_for_status(ctx, redshift, cluster_id, "available", timeout_s=180)
    assert final["ClusterStatus"] == "available", (
        f"expected the cluster to remain available after the register/deregister churn, "
        f"got {final['ClusterStatus']!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected this call to be rejected, but it succeeded with {result!r}")


_CLUSTER_BUSY = "There is an operation running on the Cluster. Please try again at a later time."


def _when_idle(call, timeout_s=300.0):
    """Run call, retrying every 2 s while the previous namespace operation still runs on the cluster."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except ClientError as err:
            error = err.response["Error"]
            if (error["Code"], error["Message"]) != ("InvalidClusterState", _CLUSTER_BUSY):
                raise
            if time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _wait_for_status(ctx, redshift, cluster_id, target_status, timeout_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
        if last["ClusterStatus"] == target_status:
            return last
        time.sleep(2)
    raise AssertionError(f"cluster never reached {target_status!r} (last seen: {last})")


# The ClusterDeleted waiter allows 1800 s, the redshift teardown budget; keep a 60 s margin.
_TEARDOWN_S = 1740.0


def _deadline(teardown_deadline: dict) -> float:
    """The run's teardown deadline, started by the first teardown that asks for it."""
    return teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_S)


def _delete_cluster(redshift, cluster_id, teardown_deadline):
    """Teardown: DeleteCluster, retrying InvalidClusterState (creating, modifying or deleting) every
    2 s, then poll every 2 s until ClusterNotFound, as the delete is asynchronous."""
    deadline = _deadline(teardown_deadline)
    while True:
        try:
            redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ClusterNotFound":
                return
            if code != "InvalidClusterState" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while True:
        try:
            redshift.describe_clusters(ClusterIdentifier=cluster_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ClusterNotFound":
                return
            raise
        if time.monotonic() >= deadline:
            raise TimeoutError(f"cluster {cluster_id} still listed at the teardown deadline")
        time.sleep(2)


def _network_redshift_subnet_group(ctx, client, teardown_deadline) -> str:
    """A Redshift cluster subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-rsg-")
    ctx.on_cleanup(lambda: _delete_subnet_group(client, name, teardown_deadline))
    client.create_cluster_subnet_group(
        ClusterSubnetGroupName=name,
        Description="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    return name


def _delete_subnet_group(client, name, teardown_deadline):
    """Teardown: DeleteClusterSubnetGroup, retrying InvalidClusterSubnetGroupStateFault (still in use)
    every 2 s; an absent group is done. The delete is synchronous."""
    deadline = _deadline(teardown_deadline)
    while True:
        try:
            client.delete_cluster_subnet_group(ClusterSubnetGroupName=name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ClusterSubnetGroupNotFoundFault":
                return
            if code != "InvalidClusterSubnetGroupStateFault" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
