"""update-cluster-network-type-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-cluster-network-type-round-trip"
GROUP = "state"
SERVICES = ["route53-recovery-control-config"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:route53-arc-cluster")
def run(ctx) -> None:
    """UpdateCluster changes the cluster's NetworkType; the cluster transitions
    DEPLOYED->PENDING->DEPLOYED and DescribeCluster reflects the new NetworkType."""
    client = ctx.client("route53-recovery-control-config")

    cluster_arn = _create_cluster_with_retry(client, ctx.unique_name("sim2real-r53arc-cluster-"))
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(client, cluster_arn))

    cluster = _poll_until(
        probe=lambda: client.describe_cluster(ClusterArn=cluster_arn)["Cluster"],
        predicate=lambda c: c["Status"] == "DEPLOYED",
        timeout_s=420.0,
        interval_s=5.0,
    )
    assert cluster["NetworkType"] == "IPV4", (
        f"expected a freshly created cluster's default NetworkType to be IPV4, got"
        f" {cluster['NetworkType']!r}"
    )

    client.update_cluster(ClusterArn=cluster_arn, NetworkType="DUALSTACK")

    cluster = _poll_until(
        probe=lambda: client.describe_cluster(ClusterArn=cluster_arn)["Cluster"],
        predicate=lambda c: c["Status"] == "DEPLOYED" and c["NetworkType"] == "DUALSTACK",
        timeout_s=420.0,
        interval_s=5.0,
    )
    assert cluster["NetworkType"] == "DUALSTACK", (
        f"expected UpdateCluster(NetworkType=DUALSTACK) to persist, got"
        f" {cluster['NetworkType']!r} from an independent DescribeCluster"
    )
    assert cluster["Status"] == "DEPLOYED", (
        f"expected the cluster to settle back to DEPLOYED after the network-type update, got"
        f" {cluster['Status']!r}"
    )


# ===== helpers =====
def _create_cluster_with_retry(client, name, timeout_s=60.0, interval_s=10.0):
    """CreateCluster, retrying ServiceQuotaExceededException for a bounded window —
    the account's 2-cluster quota may still be draining an async delete from a
    prior check's teardown."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return client.create_cluster(ClusterName=name, Tags={"sim2real": CHECK})["Cluster"][
                "ClusterArn"
            ]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ServiceQuotaExceededException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_cluster_and_wait(client, cluster_arn, timeout_s=300.0, interval_s=2.0) -> None:
    """Delete a cluster and block until it's actually gone — the account's cluster
    quota (2) is only freed once deletion truly completes, not when DeleteCluster
    returns, so the NEXT check that needs a fresh cluster must wait for this one."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            client.delete_cluster(ClusterArn=cluster_arn)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            # refused while the cluster's control panels are still being deleted
            if code not in ("ConflictException", "ValidationException") or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)
    while time.monotonic() < deadline:
        try:
            client.describe_cluster(ClusterArn=cluster_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_arn} was not deleted within {timeout_s}s")


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
