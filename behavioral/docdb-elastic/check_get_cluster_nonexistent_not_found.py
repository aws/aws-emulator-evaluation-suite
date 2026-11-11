"""get-cluster-nonexistent-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-cluster-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["docdb-elastic"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCluster on a well-formed nonexistent clusterArn fails with ResourceNotFoundException "Unable to find
    the cluster", while ListClusters on the same client succeeds."""
    client = ctx.client("docdb-elastic")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_arn = (
        f"arn:aws:docdb-elastic:{ctx.region}:{account_id}:"
        "cluster/00000000-0000-0000-0000-000000000000"
    )

    code, message = _error(lambda: client.get_cluster(clusterArn=fake_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Unable to find the cluster", f"unexpected message: {message!r}"

    # positive control: a well-formed, harmless call on the same client succeeds
    resp = client.list_clusters(maxResults=10)
    assert "clusters" in resp, f"expected a 'clusters' key in ListClusters response, got keys={sorted(resp.keys())}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected ResourceNotFoundException, but call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
