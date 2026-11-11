"""delete-cluster-lifecycle-to-gone."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-cluster-lifecycle-to-gone"
GROUP = "state"
SERVICES = ["dsql"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An unprotected cluster transitions ACTIVE -> DELETING and eventually GetCluster raises
    ResourceNotFoundException (the cluster is really gone, not merely marked); a further
    DeleteCluster against the now-dead identifier fails the same way, proving it is unusable too."""
    dsql = ctx.client("dsql")
    created = dsql.create_cluster(
        deletionProtectionEnabled=False,
        tags={"sim2real-created-with": "delete-cluster-lifecycle-to-gone"},
    )
    identifier = created["identifier"]
    ctx.on_cleanup(lambda: _best_effort_delete(dsql, identifier))

    _wait_for_status(ctx, dsql, identifier, {"ACTIVE"}, timeout_s=180)

    deleted = dsql.delete_cluster(identifier=identifier)
    assert deleted["status"] in ("DELETING", "DELETED"), (
        f"expected DeleteCluster to report DELETING or DELETED, got {deleted['status']!r}"
    )

    not_found_code = _wait_for_not_found(dsql, identifier, timeout_s=180)
    assert not_found_code == "ResourceNotFoundException", (
        f"expected GetCluster on the deleted identifier to raise ResourceNotFoundException, "
        f"got {not_found_code!r}"
    )

    redelete_code, redelete_message = _error(lambda: dsql.delete_cluster(identifier=identifier))
    assert redelete_code == "ResourceNotFoundException", (
        f"expected a second DeleteCluster against the now-gone identifier to also raise "
        f"ResourceNotFoundException, got {redelete_code!r}"
    )
    assert redelete_message == (
        f"The resource with ARN {created["arn"]} doesn't exist. Verify the ARN and try again."
    ), redelete_message


def _wait_for_status(ctx, dsql, identifier, target_statuses, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = dsql.get_cluster(identifier=identifier)
        if last["status"] in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"cluster never reached {target_statuses}, last={last}")


def _wait_for_not_found(dsql, identifier, timeout_s=180.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = dsql.get_cluster(identifier=identifier)["status"]
        except ClientError as err:
            return err.response["Error"]["Code"]
        time.sleep(interval_s)
    raise AssertionError(f"cluster {identifier} never disappeared, last status={last_status}")


def _error(fn):
    """Call fn() and return its ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _best_effort_delete(dsql, identifier):
    from botocore.exceptions import ClientError

    try:
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
