"""restore-cluster-missing-snapshot-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-cluster-missing-snapshot-not-found"
GROUP = "error-semantics"
SERVICES = ["docdb-elastic"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RestoreClusterFromSnapshot against a syntactically valid but nonexistent
    snapshotArn returns ResourceNotFoundException and creates no cluster; ListClusters
    (a call that always succeeds) still works on the same client (positive control)."""
    client = ctx.client("docdb-elastic")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_snapshot_arn = (
        f"arn:aws:docdb-elastic:{ctx.region}:{account_id}:"
        "cluster-snapshot/00000000-0000-0000-0000-000000000000"
    )
    cluster_name = ctx.unique_name("sim2real-elastic-restore-")

    code, message = _error(
        lambda: client.restore_cluster_from_snapshot(
            clusterName=cluster_name, snapshotArn=fake_snapshot_arn
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Unable to find the snapshot", f"unexpected message: {message!r}"

    # effect absent: no cluster with that name exists anywhere in the account/region
    listing = client.list_clusters(maxResults=100)
    names = [c["clusterName"] for c in listing.get("clusters", [])]
    assert cluster_name.lower() not in names, "a cluster was restored from a missing snapshot"

    # positive control: a well-formed, harmless call on the same client succeeds
    resp = client.list_clusters(maxResults=10)
    assert "clusters" in resp, f"expected a 'clusters' key in the ListClusters response, got {resp!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a restore from a nonexistent snapshot is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected ResourceNotFoundException, but the restore SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
