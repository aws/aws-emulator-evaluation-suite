"""op-contract-deleteCluster."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-deleteCluster"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteCluster deprovisions an empty cluster, is idempotent on the now-INACTIVE cluster
    (a repeat delete succeeds and leaves it INACTIVE, not ClusterNotFoundException), and rejects
    a cluster name that was never created."""
    ecs = ctx.client("ecs")

    name = ctx.unique_name("sim2real-behav-cluster-")
    ecs.create_cluster(clusterName=name)
    ctx.on_cleanup(lambda: _safe_delete_cluster(ecs, name))

    resp = ecs.delete_cluster(cluster=name)
    assert resp["cluster"]["clusterName"] == name
    assert resp["cluster"]["status"] in ("INACTIVE", "DEPROVISIONING")

    deadline = time.monotonic() + 30
    final_status = None
    while time.monotonic() < deadline:
        described = ecs.describe_clusters(clusters=[name])["clusters"]
        final_status = described[0]["status"] if described else None
        if final_status == "INACTIVE":
            break
        time.sleep(2)
    assert final_status == "INACTIVE", f"cluster never reached INACTIVE, last={final_status}"

    listed = ecs.list_clusters()["clusterArns"]
    assert not any(name in arn for arn in listed)

    # Confirmed against real AWS: DeleteCluster on an already-INACTIVE cluster is
    # idempotent (200, still INACTIVE) rather than ClusterNotFoundException — the
    # not-found error is reserved for a name that was never created at all.
    again = ecs.delete_cluster(cluster=name)["cluster"]
    assert again["clusterArn"] == resp["cluster"]["clusterArn"], (
        f"repeated DeleteCluster returned a different cluster: {again['clusterArn']}"
    )
    assert again["status"] == "INACTIVE", (
        f"repeated DeleteCluster on an INACTIVE cluster should stay INACTIVE, got {again['status']}"
    )

    err, message = _error(lambda: ecs.delete_cluster(cluster="sim2real-does-not-exist-cluster-xyz"))
    assert err == "ClusterNotFoundException", f"expected ClusterNotFoundException, got {err}"
    expected_message = 'Cluster not found.'
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _safe_delete_cluster(ecs, name):
    try:
        ecs.delete_cluster(cluster=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises: an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
