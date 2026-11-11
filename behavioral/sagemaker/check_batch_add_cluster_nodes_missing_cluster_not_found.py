"""batch-add-cluster-nodes-missing-cluster-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-add-cluster-nodes-missing-cluster-not-found"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchAddClusterNodes and DescribeCluster on a never-created HyperPod cluster name both fail with
    ResourceNotFound and their exact messages."""
    sm = ctx.client("sagemaker")
    missing_cluster_name = ctx.unique_name("sim2real-cluster-missing-")

    # positive control: the cluster-management API surface itself works
    sm.list_clusters(MaxResults=1)

    # breaking one thing: a cluster name that does not exist
    code, message = _error(
        lambda: sm.batch_add_cluster_nodes(
            ClusterName=missing_cluster_name,
            NodesToAdd=[{"InstanceGroupName": "ig-1", "IncrementTargetCountBy": 1}],
        )
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code!r}"
    expected = f"Cluster with name {missing_cluster_name} not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: still no such cluster
    describe_code, describe_message = _error(lambda: sm.describe_cluster(ClusterName=missing_cluster_name))
    assert describe_code == "ResourceNotFound", f"expected ResourceNotFound, got {describe_code!r}"
    expected_describe = f"Cluster with name {missing_cluster_name} not found"
    assert describe_message == expected_describe, f"expected message {expected_describe!r}, got {describe_message!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
