"""batch-add-cluster-nodes-cluster-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-add-cluster-nodes-cluster-not-found"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchAddClusterNodes and DescribeCluster on a never-created cluster name both fail with
    ResourceNotFound and their exact messages."""
    sm = ctx.client("sagemaker")
    bogus_cluster = ctx.unique_name("sim2real-noclus-")

    # Positive control: the cluster-management API surface itself works.
    sm.list_clusters(MaxResults=1)

    code, message = _error(
        lambda: sm.batch_add_cluster_nodes(
            ClusterName=bogus_cluster,
            NodesToAdd=[{"InstanceGroupName": "ig-0", "IncrementTargetCountBy": 1}],
        )
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code!r}"
    expected = f"Cluster with name {bogus_cluster} not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Same missing-cluster boundary surfaces identically for the read path too,
    # confirming there is genuinely no such cluster (not a partial/created state).
    describe_code, describe_message = _error(lambda: sm.describe_cluster(ClusterName=bogus_cluster))
    assert describe_code == "ResourceNotFound", f"expected ResourceNotFound, got {describe_code!r}"
    expected_describe = f"Cluster with name {bogus_cluster} not found"
    assert describe_message == expected_describe, f"expected message {expected_describe!r}, got {describe_message!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
