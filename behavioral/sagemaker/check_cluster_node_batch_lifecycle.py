"""cluster-node-batch-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-node-batch-lifecycle"
GROUP = "state-machine"
SERVICES = ["sagemaker"]

# Driving node transitions needs a provisioned HyperPod cluster; each batch node operation is
# documented to reject a nonexistent cluster with a top-level ResourceNotFound (node-level
# failures inside an existing cluster are per-entry Failed items instead).


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchAddClusterNodes, BatchRebootClusterNodes, BatchReplaceClusterNodes, BatchDeleteClusterNodes
    and DescribeCluster on a nonexistent cluster name each fail with ResourceNotFound and their exact
    message, while ListClusters succeeds on the same client."""
    sm = ctx.client("sagemaker")
    bogus_cluster = ctx.unique_name("sim2real-behav-nocluster-")
    bogus_node_id = "i-0123456789abcdef0"

    add_resp = _error_response(
        lambda: sm.batch_add_cluster_nodes(
            ClusterName=bogus_cluster,
            NodesToAdd=[{"InstanceGroupName": "worker", "IncrementTargetCountBy": 1}],
        )
    )
    assert add_resp["Code"] == "ResourceNotFound", f"BatchAddClusterNodes: expected ResourceNotFound, got {add_resp['Code']}"
    expected_add_message = f"Cluster with name {bogus_cluster} not found"
    assert add_resp["Message"] == expected_add_message, (
        f"BatchAddClusterNodes: expected message {expected_add_message!r}, got {add_resp['Message']!r}"
    )

    reboot_resp = _error_response(
        lambda: sm.batch_reboot_cluster_nodes(ClusterName=bogus_cluster, NodeIds=[bogus_node_id])
    )
    assert reboot_resp["Code"] == "ResourceNotFound", (
        f"BatchRebootClusterNodes: expected ResourceNotFound, got {reboot_resp['Code']}"
    )
    expected_reboot_message = f"Cluster with name {bogus_cluster} not found"
    assert reboot_resp["Message"] == expected_reboot_message, (
        f"BatchRebootClusterNodes: expected message {expected_reboot_message!r}, got {reboot_resp['Message']!r}"
    )

    replace_resp = _error_response(
        lambda: sm.batch_replace_cluster_nodes(ClusterName=bogus_cluster, NodeIds=[bogus_node_id])
    )
    assert replace_resp["Code"] == "ResourceNotFound", (
        f"BatchReplaceClusterNodes: expected ResourceNotFound, got {replace_resp['Code']}"
    )
    expected_replace_message = f"Cluster with name {bogus_cluster} not found"
    assert replace_resp["Message"] == expected_replace_message, (
        f"BatchReplaceClusterNodes: expected message {expected_replace_message!r}, got {replace_resp['Message']!r}"
    )

    delete_resp = _error_response(
        lambda: sm.batch_delete_cluster_nodes(ClusterName=bogus_cluster, NodeIds=[bogus_node_id])
    )
    assert delete_resp["Code"] == "ResourceNotFound", (
        f"BatchDeleteClusterNodes: expected ResourceNotFound, got {delete_resp['Code']}"
    )
    expected_delete_message = f"Cluster with name {bogus_cluster} not found"
    assert delete_resp["Message"] == expected_delete_message, (
        f"BatchDeleteClusterNodes: expected message {expected_delete_message!r}, got {delete_resp['Message']!r}"
    )

    # effect absent, on the actual response body: none of the calls reported the bogus
    # node as having been touched successfully.
    for label, resp in (
        ("add", add_resp),
        ("reboot", reboot_resp),
        ("replace", replace_resp),
        ("delete", delete_resp),
    ):
        assert bogus_node_id not in resp.get("Message", ""), (
            f"BatchAddClusterNodes/{label}: error message unexpectedly references a real node"
        )

    # positive control: ListClusters succeeds, so the refusals above distinguish a missing cluster
    # rather than blanket-rejecting every HyperPod cluster call.
    list_resp = sm.list_clusters(MaxResults=1)
    assert "ClusterSummaries" in list_resp, f"ListClusters response missing ClusterSummaries: {list_resp}"

    # terminal, independent read at the destination: none of the four rejected batch calls
    # conjured the cluster into existence either - a describe through a fifth, unrelated
    # operation still reports the same ResourceNotFound.
    describe_resp = _error_response(lambda: sm.describe_cluster(ClusterName=bogus_cluster))
    assert describe_resp["Code"] == "ResourceNotFound", (
        f"DescribeCluster: expected ResourceNotFound, got {describe_resp['Code']}"
    )
    expected_describe_message = f"Cluster with name {bogus_cluster} not found"
    assert describe_resp["Message"] == expected_describe_message, (
        f"DescribeCluster: expected message {expected_describe_message!r}, got {describe_resp['Message']!r}"
    )


def _error_response(fn):
    """Return the full Error dict (Code + Message) of a rejected call; an unexpected success
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
