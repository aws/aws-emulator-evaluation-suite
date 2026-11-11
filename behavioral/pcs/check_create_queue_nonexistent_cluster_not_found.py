"""create-queue-nonexistent-cluster-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-queue-nonexistent-cluster-not-found"
GROUP = "error-semantics"
SERVICES = ["pcs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateQueue and ListQueues on a nonexistent clusterIdentifier get ResourceNotFoundException
    "AWS PCS couldn't find the cluster you specified.", while ListClusters returns a list."""
    pcs = ctx.client("pcs")
    bogus_cluster = "pcs_" + ("2" * 20)
    queue_name = ctx.unique_name("sim2real-q-").replace("_", "-")

    error = _client_error(
        lambda: pcs.create_queue(clusterIdentifier=bogus_cluster, queueName=queue_name)
    )
    _assert_error(error, "ResourceNotFoundException", _CLUSTER_NOT_FOUND)

    # Effect absent: there is no queue anywhere under that (nonexistent) cluster.
    list_error = _client_error(lambda: pcs.list_queues(clusterIdentifier=bogus_cluster))
    _assert_error(list_error, "ResourceNotFoundException", _CLUSTER_NOT_FOUND)

    # Positive control: the client can still talk to the service for a
    # legitimate read-only call.
    resp = pcs.list_clusters(maxResults=1)
    clusters = resp.get("clusters")
    assert isinstance(clusters, list), f"expected ListClusters to return a list, got {clusters!r}"


_CLUSTER_NOT_FOUND = "AWS PCS couldn't find the cluster you specified."


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _assert_error(error, code, message):
    assert error.get("Code") == code, f"expected {code}, got {error.get('Code')!r}"
    assert error.get("Message") == message, (
        f"expected message {message!r}, got {error.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
