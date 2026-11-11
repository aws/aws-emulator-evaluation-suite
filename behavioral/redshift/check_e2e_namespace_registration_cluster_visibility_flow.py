"""e2e-namespace-registration-cluster-visibility-flow."""
from __future__ import annotations

import secrets
import string
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-namespace-registration-cluster-visibility-flow"
GROUP = "e2e"
SERVICES = ["redshift"]

MSG_IN_TRANSITION = "Cluster {cluster_id} is not in available state."
MSG_OPERATION_RUNNING = "There is an operation running on the Cluster. Please try again at a later time."


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterNamespace for the cluster's own account leaves the cluster 'modifying', a second
    namespace call meanwhile is InvalidClusterState, and DeregisterNamespace later succeeds
    with the cluster settling 'available'.
    """
    redshift = ctx.client("redshift")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    cluster_id = _create_available_cluster(ctx, redshift)
    namespace_id = {"ProvisionedIdentifier": {"ClusterIdentifier": cluster_id}}

    # A self-consumer registration is never refused as already/never registered; the observable
    # effect is the cluster leaving 'available' while it applies.
    concurrent_code, concurrent_message = _deregister_while_register_applies(
        ctx, redshift, cluster_id, namespace_id, account_id
    )
    assert concurrent_code == "InvalidClusterState", (
        f"a namespace operation issued while the prior one is still applying must be "
        f"rejected with InvalidClusterState, got {concurrent_code!r}"
    )
    # Redshift words this refusal either way while the registration applies.
    if concurrent_message != MSG_OPERATION_RUNNING:
        expected = MSG_IN_TRANSITION.format(cluster_id=cluster_id)
        assert concurrent_message == expected, (
            f"expected {expected!r} or {MSG_OPERATION_RUNNING!r}, got {concurrent_message!r}"
        )

    _wait_available(redshift, cluster_id, timeout_s=_budget_s(ctx, 300), ctx=ctx)

    # Positive control: once available again, DeregisterNamespace succeeds.
    deregister_resp = _while_cluster_busy(
        lambda: redshift.deregister_namespace(
            NamespaceIdentifier=namespace_id, ConsumerIdentifiers=[account_id]
        ),
        timeout_s=_budget_s(ctx, 300),
        ctx=ctx,
    )
    assert deregister_resp["Status"] == "Deregistering", (
        f"expected Status='Deregistering', got {deregister_resp['Status']!r}"
    )

    final_status = _wait_available(redshift, cluster_id, timeout_s=_budget_s(ctx, 300), ctx=ctx)
    assert final_status == "available", f"expected cluster to settle 'available', got {final_status!r}"


#: Register-then-deregister rounds tried for a DeregisterNamespace that lands while the register applies.
_APPLY_WINDOW_ATTEMPTS = 3


def _deregister_while_register_applies(ctx, redshift, cluster_id, namespace_id, account_id):
    """RegisterNamespace (answering 'Registering'), a ClusterStatus read, then DeregisterNamespace;
    return the deregister's refusal ``(code, message)`` from the round whose read saw the cluster
    'modifying'. A deregister accepted after a 'modifying' read is followed by a second read: still
    'modifying' fails the check, since the cluster accepted it while the register applied. A round
    whose first read saw the register already applied, or whose second read shows it no longer
    'modifying', lets the cluster settle and runs again, up to the cap."""
    rounds = []
    for _ in range(_APPLY_WINDOW_ATTEMPTS):
        register_resp = _while_cluster_busy(
            lambda: redshift.register_namespace(
                NamespaceIdentifier=namespace_id, ConsumerIdentifiers=[account_id]
            ),
            timeout_s=_budget_s(ctx, 300),
            ctx=ctx,
        )
        assert register_resp["Status"] == "Registering", (
            f"expected Status='Registering', got {register_resp['Status']!r}"
        )
        status_right_after = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0][
            "ClusterStatus"
        ]
        if status_right_after == "modifying":
            try:
                result = redshift.deregister_namespace(
                    NamespaceIdentifier=namespace_id, ConsumerIdentifiers=[account_id]
                )
            except ClientError as err:
                return err.response["Error"]["Code"], err.response["Error"].get("Message")
            status_after_accept = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0][
                "ClusterStatus"
            ]
            assert status_after_accept != "modifying", (
                f"DeregisterNamespace was accepted ({result['Status']!r}) on a cluster that read "
                f"'modifying' right after RegisterNamespace and still reads 'modifying'"
            )
            rounds.append((status_right_after, result["Status"]))
        else:
            rounds.append((status_right_after, None))
        _wait_available(redshift, cluster_id, timeout_s=_budget_s(ctx, 300), ctx=ctx)
    raise AssertionError(
        f"RegisterNamespace never left the cluster 'modifying' long enough for a second namespace "
        f"call to be refused; (status read, deregister answer) per round: {rounds}"
    )


def _generate_password() -> str:
    alphabet = string.ascii_letters + string.digits
    body = "".join(secrets.choice(alphabet) for _ in range(20))
    return "Aa1" + body


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _while_cluster_busy(fn, *, timeout_s: float, interval_s: float = 2.0, ctx=None):
    """Call fn, re-calling it while Redshift refuses it because an operation still runs on a
    cluster DescribeClusters already reports 'available'; any other error raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "InvalidClusterState" or err.get("Message") != MSG_OPERATION_RUNNING:
                raise
            if time.monotonic() >= deadline:
                if ctx is not None and _budget_spent(ctx):
                    raise TimeoutError("cluster accepting the namespace call: the run budget ended first; not graded") from exc
                raise AssertionError(f"cluster still busy after {timeout_s:.0f}s: {exc}") from exc
        time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("polled condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


def _wait_available(redshift: Any, cluster_id: str, timeout_s: float = 300, ctx=None) -> str:
    return _poll_until(
        probe=lambda: redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]["ClusterStatus"],
        predicate=lambda s: s == "available",
        timeout_s=timeout_s,
        interval_s=1,
        ctx=ctx,
    )


def _create_available_cluster(ctx: Any, redshift: Any) -> str:
    cluster_id = ctx.unique_name("sim2real-rsns-").lower().replace("_", "-")
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType="ra3.xlplus",
        ClusterType="single-node",
        MasterUsername="s2radmin",
        MasterUserPassword=_generate_password(),
        DBName="dev",
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_cluster(redshift, cluster_id))
    _poll_until(
        probe=lambda: redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]["ClusterStatus"],
        predicate=lambda s: s == "available",
        timeout_s=_budget_s(ctx, 900),
        interval_s=1,
        ctx=ctx,
    )
    return cluster_id


def _delete_cluster(redshift: Any, cluster_id: str) -> None:
    # A cluster still 'modifying' from a namespace operation refuses DeleteCluster.
    try:
        _wait_available(redshift, cluster_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFound":
            raise
    try:
        redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFound":
            raise
        return
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        try:
            redshift.describe_clusters(ClusterIdentifier=cluster_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFound":
                raise
            return
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
