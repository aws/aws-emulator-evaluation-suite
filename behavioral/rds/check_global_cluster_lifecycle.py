"""global-cluster-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "global-cluster-lifecycle"
GROUP = 'global_clusters'
SERVICES = ['rds']

ERR_GLOBAL_CLUSTER_NOT_FOUND = "GlobalClusterNotFoundFault"


def _delete_unless_gone(delete, gone_code):
    """Teardown delete; an already-deleted resource answers ``gone_code`` (documented not-found)."""
    try:
        delete()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != gone_code:
            raise


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGlobalCluster -> available; DeleteGlobalCluster removes it and mutations on it fail."""
    rds = ctx.client("rds")
    account = ctx.client("sts").get_caller_identity()["Account"]
    global_id = ctx.unique_name("sim2real-behav-gclu-")
    rds.create_global_cluster(
        GlobalClusterIdentifier=global_id,
        Engine="aurora-mysql",
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_unless_gone(
        lambda: rds.delete_global_cluster(GlobalClusterIdentifier=global_id), "GlobalClusterNotFoundFault"))

    def _describe():
        try:
            clusters = rds.describe_global_clusters(
                GlobalClusterIdentifier=global_id
            ).get("GlobalClusters", [])
        except ClientError as _e:
            if _e.response.get("Error", {}).get("Code") == ERR_GLOBAL_CLUSTER_NOT_FOUND:
                return None
            raise
        return clusters[0] if clusters else None

    deadline = time.monotonic() + 300
    gc = None
    while time.monotonic() < deadline:
        gc = _describe()
        if gc is not None and gc.get("Status") == "available":
            break
        time.sleep(5)
    else:
        raise AssertionError(f"global cluster {global_id} available not met in time")
    assert gc["Engine"] == "aurora-mysql", f"expected engine aurora-mysql, got {gc.get('Engine')!r}"
    expected_arn = f"arn:aws:rds::{account}:global-cluster:{global_id}"
    assert gc["GlobalClusterArn"] == expected_arn, (
        f"expected GlobalClusterArn {expected_arn!r}, got {gc.get('GlobalClusterArn')!r}"
    )
    assert gc["GlobalClusterResourceId"], "expected a server-generated GlobalClusterResourceId"

    rds.delete_global_cluster(GlobalClusterIdentifier=global_id)
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        if _describe() is None:
            break
        time.sleep(5)
    else:
        raise AssertionError(f"global cluster {global_id} deletion not met in time")

    # The delete already proved absence via a specific not-found on describe; also prove the
    # dead id is unusable for a mutation, not just unreadable.
    try:
        rds.delete_global_cluster(GlobalClusterIdentifier=global_id)
        raise AssertionError("expected delete_global_cluster on an already-deleted id to fail")
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        assert code == ERR_GLOBAL_CLUSTER_NOT_FOUND, (
            f"expected {ERR_GLOBAL_CLUSTER_NOT_FOUND} on a repeat delete, got {code!r}"
        )
        message = e.response.get("Error", {}).get("Message")
        assert message == f"Global cluster '{global_id}' not found", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
