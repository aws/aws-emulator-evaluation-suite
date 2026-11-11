"""namespace-register-deregister-lifecycle."""
from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "namespace-register-deregister-lifecycle"
GROUP = "state-machine"
SERVICES = ["redshift"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Self-account Register/DeregisterNamespace succeed in any order (no InvalidNamespaceFault when
    nothing is registered), and each call moves the cluster out of 'available' per DescribeClusters
    before it settles back, proving real backend work rather than a canned Status."""
    redshift = ctx.client("redshift")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    cluster_id = _create_available_cluster(ctx)
    namespace_id = {"ProvisionedIdentifier": {"ClusterIdentifier": cluster_id}}

    def call_and_verify(op_name: str, fn, expected_status: str) -> None:
        resp = _while_cluster_busy(fn, op_name, _budget_s(ctx, 300.0), ctx=ctx)
        assert resp["Status"] == expected_status, (
            f"{op_name}: expected Status {expected_status!r}, got {resp['Status']!r}"
        )
        _confirm_transient_modification(redshift, cluster_id, op_name)
        _wait_cluster_available(redshift, cluster_id, timeout_s=_budget_s(ctx, 300.0), ctx=ctx)

    # DeregisterNamespace accepts a namespace that was never registered -- no
    # InvalidNamespaceFault for a self-account consumer -- and still does real work.
    call_and_verify(
        "DeregisterNamespace (nothing registered yet)",
        lambda: redshift.deregister_namespace(
            NamespaceIdentifier=namespace_id, ConsumerIdentifiers=[account_id]
        ),
        "Deregistering",
    )

    call_and_verify(
        "RegisterNamespace",
        lambda: redshift.register_namespace(
            NamespaceIdentifier=namespace_id, ConsumerIdentifiers=[account_id]
        ),
        "Registering",
    )

    call_and_verify(
        "DeregisterNamespace",
        lambda: redshift.deregister_namespace(
            NamespaceIdentifier=namespace_id, ConsumerIdentifiers=[account_id]
        ),
        "Deregistering",
    )

    # The lifecycle is clean: after deregistering, registering again does real work
    # again rather than getting stuck.
    call_and_verify(
        "RegisterNamespace (after a full cycle)",
        lambda: redshift.register_namespace(
            NamespaceIdentifier=namespace_id, ConsumerIdentifiers=[account_id]
        ),
        "Registering",
    )

    # Final teardown of the namespace registration, then the terminal independent
    # read: the cluster is genuinely back to available, not left mid-mutation.
    _while_cluster_busy(
        lambda: redshift.deregister_namespace(
            NamespaceIdentifier=namespace_id, ConsumerIdentifiers=[account_id]
        ),
        "DeregisterNamespace (final)",
        _budget_s(ctx, 300.0),
        ctx=ctx,
    )
    final_status = _wait_cluster_available(redshift, cluster_id, timeout_s=_budget_s(ctx, 300.0), ctx=ctx)
    assert final_status == "available", (
        f"expected cluster {cluster_id} to settle back to available after the full "
        f"lifecycle, got {final_status!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _cluster_busy(exc: ClientError) -> bool:
    """The InvalidClusterState refusal Redshift returns while a namespace operation still runs on a
    cluster that DescribeClusters already reports 'available'."""
    err = exc.response["Error"]
    return err["Code"] in ("InvalidClusterState", "InvalidClusterStateFault") and (
        "operation running on the Cluster" in err.get("Message", "")
    )


def _while_cluster_busy(fn, op_name: str, timeout_s: float, interval_s: float = 2.0, ctx=None):
    """Call fn, re-calling it every interval_s while the cluster refuses it as busy, until
    timeout_s; any other error, or a busy refusal past timeout_s, raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if not _cluster_busy(exc):
                raise
            if time.monotonic() >= deadline:
                if ctx is not None and _budget_spent(ctx):
                    raise TimeoutError(f"{op_name} accepted: the run budget ended first; not graded") from exc
                raise AssertionError(
                    f"{op_name}: the cluster still reported an operation running {timeout_s:.0f}s "
                    f"after it first refused the call: {exc}"
                ) from exc
        time.sleep(interval_s)


def _confirm_transient_modification(
    redshift, cluster_id: str, op_name: str, attempts: int = 20, interval_s: float = 0.25
) -> None:
    """Independent-read proof (DescribeClusters, never the mutating op's own response)
    that `op_name` did real backend work: within a short bounded window the cluster
    must be observed leaving 'available'. A target that fakes the Status without
    touching the cluster would read 'available' for the whole window."""
    status = "available"
    for _ in range(attempts):
        status = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0][
            "ClusterStatus"
        ]
        if status != "available":
            return
        time.sleep(interval_s)
    assert status != "available", (
        f"{op_name}: expected DescribeClusters to observe the cluster leave 'available' "
        f"within {attempts * interval_s:.0f}s of the call, but it stayed 'available' the "
        f"whole time -- indistinguishable from a no-op that never reached AWS"
    )


def _wait_cluster_available(
    redshift, cluster_id: str, timeout_s: float = 300.0, interval_s: float = 1.0, ctx=None
) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0][
            "ClusterStatus"
        ]
        if last == "available":
            return last
        time.sleep(interval_s)
    if last != "available" and ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_id} available: the run budget ended first; not graded")
    assert last == "available", (
        f"cluster {cluster_id} did not settle back to 'available' within {timeout_s}s "
        f"(last observed: {last!r})"
    )
    return last


def _rand_password() -> str:
    return f"S2r{secrets.token_hex(4)}Aa1Xy"


def _default_vpc_subnets(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region to build a Redshift cluster subnet "
            "group from; a non-shared network VPC + subnets would need to be provisioned first"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    by_az: dict[str, str] = {}
    for subnet in subnets:
        by_az.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
    if not by_az:
        raise AssertionError("shared network has no subnets available")
    return list(by_az.values())


def _create_available_cluster(ctx) -> str:
    """Create a single-node Redshift cluster and wait for it to become available.
    Registers cleanup (delete cluster + subnet group) and returns the cluster id."""
    redshift = ctx.client("redshift")
    subnet_ids = _default_vpc_subnets(ctx)
    subnet_group_name = ctx.unique_name("sim2real-subg-")
    redshift.create_cluster_subnet_group(
        ClusterSubnetGroupName=subnet_group_name,
        Description="sim2real behavioral fidelity check",
        SubnetIds=subnet_ids[:2] if len(subnet_ids) > 1 else subnet_ids,
        Tags=[{"Key": "sim2real-behavioral", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: _safe_delete_subnet_group(redshift, subnet_group_name)
    )

    cluster_id = ctx.unique_name("sim2real-clu-")
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType="ra3.xlplus",
        ClusterType="single-node",
        MasterUsername="s2radmin",
        MasterUserPassword=_rand_password(),
        ClusterSubnetGroupName=subnet_group_name,
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-behavioral", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_cluster(redshift, cluster_id))

    waiter = redshift.get_waiter("cluster_available")
    try:
        waiter.wait(
            ClusterIdentifier=cluster_id,
            WaiterConfig={"Delay": 2, "MaxAttempts": max(1, int(_budget_s(ctx, 1800.0) // 2))},
        )
    except WaiterError as exc:
        if "Max attempts exceeded" in str(exc) and _budget_spent(ctx):
            raise TimeoutError(f"cluster {cluster_id} available: the run budget ended first; not graded") from exc
        raise AssertionError(f"cluster {cluster_id} never became available: {exc}")
    return cluster_id


def _delete_cluster(redshift, cluster_id: str) -> None:
    try:
        _while_cluster_busy(
            lambda: redshift.delete_cluster(
                ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True
            ),
            "DeleteCluster",
            1800.0,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ClusterNotFoundFault":
            return
        raise
    waiter = redshift.get_waiter("cluster_deleted")
    try:
        waiter.wait(
            ClusterIdentifier=cluster_id,
            WaiterConfig={"Delay": 2, "MaxAttempts": 900},
        )
    except WaiterError as last:
        raise RuntimeError(f"redshift cluster {cluster_id} was not deleted: {last!r}") from last


def _safe_delete_subnet_group(redshift, name: str) -> None:
    last = None
    for _ in range(150):
        try:
            redshift.delete_cluster_subnet_group(ClusterSubnetGroupName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterSubnetGroupNotFoundFault":
                return
            if code == "InvalidClusterSubnetGroupStateFault":
                last = exc
                time.sleep(2)
                continue
            raise
    raise RuntimeError(f"cluster subnet group {name} was not deleted: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
