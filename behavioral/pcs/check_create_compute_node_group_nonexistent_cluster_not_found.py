"""create-compute-node-group-nonexistent-cluster-not-found."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-compute-node-group-nonexistent-cluster-not-found"
GROUP = "error-semantics"
SERVICES = ["pcs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateComputeNodeGroup on a nonexistent cluster with a nonexistent instance profile gets
    ValidationException naming the profile (IAM request id masked), while Get, List and
    DeleteComputeNodeGroup on that cluster get ResourceNotFoundException with their exact messages."""
    pcs = ctx.client("pcs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bogus_cluster = "pcs_" + ("1" * 20)
    cng_name = ctx.unique_name("sim2real-cng-").replace("_", "-")[:24]

    create_error = _client_error(
        lambda: pcs.create_compute_node_group(
            clusterIdentifier=bogus_cluster,
            computeNodeGroupName=cng_name,
            subnetIds=["subnet-" + ("0" * 17)],
            customLaunchTemplate={"id": "lt-" + ("0" * 17), "version": "1"},
            iamInstanceProfileArn=f"arn:aws:iam::{account}:instance-profile/sim2real-nonexistent",
            scalingConfiguration={"minInstanceCount": 0, "maxInstanceCount": 0},
            instanceConfigs=[{"instanceType": "c5.large"}],
        )
    )
    assert create_error.get("Code") == "ValidationException", (
        "expected ValidationException (the nonexistent IAM instance profile short-circuits "
        f"cluster resolution), got {create_error.get('Code')}"
    )
    # message varies: it embeds the per-call IAM request id and PCS's SDK attempt count, so
    # those two tokens are normalised and the rest of the string is compared exactly.
    normalised = re.sub(
        r"Request ID: [0-9a-f-]{36}\) \(SDK Attempt Count: \d+\)",
        "Request ID: <request-id>) (SDK Attempt Count: <n>)",
        create_error.get("Message", ""),
    )
    expected_create_message = (
        "Instance Profile sim2real-nonexistent cannot be found. (Service: Iam, Status Code: 404, "
        "Request ID: <request-id>) (SDK Attempt Count: <n>)"
    )
    assert normalised == expected_create_message, (
        f"expected message {expected_create_message!r}, got {create_error.get('Message')!r}"
    )

    get_error = _client_error(
        lambda: pcs.get_compute_node_group(
            clusterIdentifier=bogus_cluster, computeNodeGroupIdentifier="pcs_" + ("2" * 20)
        )
    )
    _assert_error(get_error, "ResourceNotFoundException", _CLUSTER_NOT_FOUND)

    # Effect absent + positive control: listing node groups for that same
    # nonexistent cluster fails the same deterministic way, it never reports
    # a node group as having been created underneath a phantom cluster.
    list_error = _client_error(lambda: pcs.list_compute_node_groups(clusterIdentifier=bogus_cluster))
    _assert_error(list_error, "ResourceNotFoundException", _CLUSTER_NOT_FOUND)

    delete_error = _client_error(
        lambda: pcs.delete_compute_node_group(
            clusterIdentifier=bogus_cluster, computeNodeGroupIdentifier="pcs_" + ("2" * 20)
        )
    )
    _assert_error(delete_error, "ResourceNotFoundException", _CLUSTER_NOT_FOUND)

    # Positive control: the client can still talk to the service for a
    # legitimate read-only call, so the rejections above are specific to the
    # bogus cluster/profile, not a universally-denied credential.
    resp = pcs.list_clusters(maxResults=1)
    clusters = resp.get("clusters")
    assert isinstance(clusters, list), f"expected ListClusters to return a list, got {clusters!r}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


_CLUSTER_NOT_FOUND = "AWS PCS couldn't find the cluster you specified."


def _assert_error(error, code, message):
    assert error.get("Code") == code, f"expected {code}, got {error.get('Code')!r}"
    assert error.get("Message") == message, (
        f"expected message {message!r}, got {error.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
