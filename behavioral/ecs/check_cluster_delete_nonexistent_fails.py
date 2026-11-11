"""cluster-delete-nonexistent-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-delete-nonexistent-fails"
GROUP = 'overly-permissive'
SERVICES = ['ecs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCluster on a real cluster leaves it INACTIVE, while on a never-created name it is
    refused ClusterNotFoundException with the message 'Cluster not found.'."""
    ecs = ctx.client("ecs")

    # --- positive control: DeleteCluster on a real, empty cluster succeeds ---
    real_name = ctx.unique_name("sim2real-behav-ecs-cluster-real-")
    ecs.create_cluster(clusterName=real_name)
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.delete_cluster(cluster=real_name)))

    ecs.delete_cluster(cluster=real_name)

    deadline = time.monotonic() + 30
    final_status = None
    while time.monotonic() < deadline:
        described = ecs.describe_clusters(clusters=[real_name])["clusters"]
        final_status = described[0]["status"] if described else None
        if final_status == "INACTIVE":
            break
        time.sleep(2)
    assert final_status == "INACTIVE", (
        f"positive control: real cluster never reached INACTIVE after delete, last={final_status}"
    )

    # --- negative: deleting a cluster that never existed is rejected ---
    bogus = ctx.unique_name("sim2real-behav-ecs-cluster-missing-")
    code, message = _error(lambda: ecs.delete_cluster(cluster=bogus))
    assert code == "ClusterNotFoundException", f"unexpected error code: {code}"
    assert message == "Cluster not found.", f"unexpected message: {message!r}"


def _error(fn):
    """Call fn(); return its (code, message). A success raises: the call must be refused."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
