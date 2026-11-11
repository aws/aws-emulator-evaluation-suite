"""cluster-node-batch-add-delete-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "cluster-node-batch-add-delete-lifecycle"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator accepting a mutating call against a nonexistent cluster is the strongest signal
    available."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        error = getattr(exc, "response", {}).get("Error", {})
        if error.get("Code") is None:
            raise
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ResourceNotFound rejection, but the call SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchAddClusterNodes, BatchDeleteClusterNodes and DescribeCluster on a cluster name that does not
    exist each fail with ResourceNotFound and their exact message, so no partly created cluster state
    is visible."""
    sm = ctx.client("sagemaker")
    bogus_cluster_name = ctx.unique_name("sim2real-behav-nocluster-")

    add_code, add_message = _error(
        lambda: sm.batch_add_cluster_nodes(
            ClusterName=bogus_cluster_name,
            NodesToAdd=[{"InstanceGroupName": "worker", "IncrementTargetCountBy": 1}],
        )
    )
    assert add_code == "ResourceNotFound", f"BatchAddClusterNodes: expected ResourceNotFound, got {add_code!r}"
    expected_add_message = f"Cluster with name {bogus_cluster_name} not found"
    assert add_message == expected_add_message, (
        f"BatchAddClusterNodes: expected message {expected_add_message!r}, got {add_message!r}"
    )

    delete_code, delete_message = _error(
        lambda: sm.batch_delete_cluster_nodes(
            ClusterName=bogus_cluster_name, NodeIds=["i-0123456789abcdef0"]
        )
    )
    assert delete_code == "ResourceNotFound", (
        f"BatchDeleteClusterNodes: expected ResourceNotFound, got {delete_code!r}"
    )
    expected_delete_message = f"Cluster with name {bogus_cluster_name} not found"
    assert delete_message == expected_delete_message, (
        f"BatchDeleteClusterNodes: expected message {expected_delete_message!r}, got {delete_message!r}"
    )

    # Effect absent: the rejected calls didn't conjure a cluster into existence either.
    describe_code, describe_message = _error(lambda: sm.describe_cluster(ClusterName=bogus_cluster_name))
    assert describe_code == "ResourceNotFound", (
        f"DescribeCluster: expected ResourceNotFound, got {describe_code!r}"
    )
    expected_describe_message = f"Cluster with name {bogus_cluster_name} not found"
    assert describe_message == expected_describe_message, (
        f"DescribeCluster: expected message {expected_describe_message!r}, got {describe_message!r}"
    )

    # Positive control: a real, always-answerable cluster call succeeds on this same client,
    # ruling out a client/emulator that blanket-rejects every SageMaker HyperPod call rather
    # than genuinely distinguishing a missing cluster from a working one.
    sm.list_clusters(MaxResults=1)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
