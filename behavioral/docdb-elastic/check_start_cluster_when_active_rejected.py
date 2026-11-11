"""start-cluster-when-active-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-cluster-when-active-rejected"
GROUP = "overly-permissive"
SERVICES = ["docdb-elastic"]

_ADMIN_USER = "sim2realadmin"
_ADMIN_PASSWORD = "Sim2RealPassw0rd123"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartCluster on an ACTIVE cluster fails with ValidationException and its exact message and the cluster
    stays ACTIVE; once STOPPED, the same cluster starts and returns to ACTIVE."""
    client = ctx.client("docdb-elastic")
    name = ctx.unique_name("sim2real-elastic-startact-")

    cluster_arn = client.create_cluster(
        clusterName=name,
        authType="PLAIN_TEXT",
        adminUserName=_ADMIN_USER,
        adminUserPassword=_ADMIN_PASSWORD,
        shardCapacity=2,
        shardCount=1,
        tags={"sim2real-check": CHECK},
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(client, cluster_arn, time.monotonic() + _TEARDOWN_S))
    _wait_for_status(client, cluster_arn, {"ACTIVE"})

    code, message = _error_code(lambda: _retry_in_use(lambda: client.start_cluster(clusterArn=cluster_arn)))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = "Can't start the cluster as it's currently in state unavailable for starting."
    assert message == expected, f"unexpected message: {message!r}"

    # effect absent: cluster is still ACTIVE, no STARTING transition was triggered
    still_active = client.get_cluster(clusterArn=cluster_arn)["cluster"]
    assert still_active["status"] == "ACTIVE", (
        f"expected status ACTIVE (unaffected by the rejected StartCluster), "
        f"got {still_active['status']!r}"
    )

    # positive control: stop, then StartCluster succeeds and reaches ACTIVE again
    _retry_in_use(lambda: client.stop_cluster(clusterArn=cluster_arn))
    _wait_for_status(client, cluster_arn, {"STOPPED"})
    _retry_in_use(lambda: client.start_cluster(clusterArn=cluster_arn))
    restarted = _wait_for_status(client, cluster_arn, {"ACTIVE"})
    assert restarted["status"] == "ACTIVE", (
        f"expected StartCluster on a STOPPED cluster to reach ACTIVE, "
        f"got {restarted['status']!r}"
    )


def _error_code(fn):
    """Call fn(); return the botocore (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS rejects is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected StartCluster to be rejected, but it SUCCEEDED: {result!r}")


def _wait_for_status(client, cluster_arn, target_statuses, timeout_s=1800.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        cluster = client.get_cluster(clusterArn=cluster_arn)["cluster"]
        last_status = cluster["status"]
        if last_status in target_statuses:
            return cluster
        time.sleep(interval_s)
    raise AssertionError(f"cluster never reached {target_statuses}, last status={last_status}")


# StartCluster, StopCluster and DeleteCluster answer ValidationException with this message for a while
# after GetCluster reports a settled status, until the service releases the cluster.
_IN_USE = "Can't perform operation on cluster as it's in use"


def _in_use(exc):
    err = exc.response["Error"]
    return err["Code"] == "ValidationException" and (err.get("Message") or "").startswith(_IN_USE)


def _retry_in_use(fn, timeout_s=600.0, interval_s=15.0):
    """Call fn(), retrying while the cluster is still in use; any other answer is returned or raised."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if not _in_use(exc) or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


# Inside the 1800 s docdb-elastic cleanup budget.
_TEARDOWN_S = 1680.0
# Documented cluster statuses that are a transition in progress: StartCluster and DeleteCluster wait them out.
_TRANSITIONAL = {
    "CREATING", "UPDATING", "MODIFYING", "MERGING", "SPLITTING", "COPYING", "STARTING", "STOPPING", "MAINTENANCE",
}
# DeleteCluster and StartCluster answer ValidationException with these messages while the cluster is in a
# state that refuses them; a STOPPED elastic cluster cannot be deleted until it is started.
_REFUSED_FOR_STATE = (
    "Can't delete the cluster because it is in ",
    "Can't start the cluster as it's currently in state",
)


def _refused_for_state(exc):
    err = exc.response["Error"]
    message = err.get("Message") or ""
    return err["Code"] == "ConflictException" or _in_use(exc) or (
        err["Code"] == "ValidationException" and message.startswith(_REFUSED_FOR_STATE)
    )


def _delete_cluster(client, cluster_arn, deadline):
    """Wait for the cluster to leave any transitional status, start it when STOPPED, delete it, and poll every
    2 s until GetCluster answers not-found; a refusal while the cluster is busy is retried until ``deadline``.
    A cluster gone is done; any other failure, or the deadline passing, raises."""
    status = None
    while True:
        try:
            status = client.get_cluster(clusterArn=cluster_arn)["cluster"]["status"]
            if status == "STOPPED":
                client.start_cluster(clusterArn=cluster_arn)
            elif status not in _TRANSITIONAL and status != "DELETING":
                client.delete_cluster(clusterArn=cluster_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            if not _refused_for_state(exc):
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {cluster_arn} still {status!r} at the teardown deadline; not deleted")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
