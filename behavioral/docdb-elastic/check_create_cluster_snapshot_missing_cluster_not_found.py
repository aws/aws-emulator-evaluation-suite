"""create-cluster-snapshot-missing-cluster-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-cluster-snapshot-missing-cluster-not-found"
GROUP = "error-semantics"
SERVICES = ["docdb-elastic"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateClusterSnapshot against a syntactically valid but nonexistent clusterArn
    returns ResourceNotFoundException and creates no snapshot; ListClusterSnapshots (a
    call that always succeeds) still works on the same client (positive control)."""
    client = ctx.client("docdb-elastic")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_cluster_arn = (
        f"arn:aws:docdb-elastic:{ctx.region}:{account_id}:"
        "cluster/00000000-0000-0000-0000-000000000000"
    )
    snapshot_name = ctx.unique_name("sim2real-elastic-snap-")

    code, message = _error(
        lambda: client.create_cluster_snapshot(
            clusterArn=fake_cluster_arn, snapshotName=snapshot_name
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Unable to find the cluster", f"unexpected message: {message!r}"

    # effect absent: no snapshot with that name exists anywhere in the account/region
    listing = client.list_cluster_snapshots(maxResults=100)
    names = [s["snapshotName"] for s in listing.get("snapshots", [])]
    assert snapshot_name.lower() not in names, "a snapshot was created against a missing cluster"

    # positive control: a well-formed, harmless call on the same client succeeds
    # (ListClusterSnapshots requires maxResults in [20, 100]; below 20 is rejected client-side)
    resp = client.list_cluster_snapshots(maxResults=20)
    assert "snapshots" in resp, f"expected a snapshots key in the response, got {resp!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected CreateClusterSnapshot against a missing cluster to be rejected, "
        f"but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
