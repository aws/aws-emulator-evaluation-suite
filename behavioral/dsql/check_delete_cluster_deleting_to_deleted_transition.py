"""delete-cluster-deleting-to-deleted-transition."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-cluster-deleting-to-deleted-transition"
GROUP = "state"
SERVICES = ["dsql"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteCluster moves an unprotected ACTIVE cluster through DELETING to gone, and the dead
    identifier then rejects a further delete as not-found (not merely unreadable)."""
    dsql = ctx.client("dsql")
    created = dsql.create_cluster(deletionProtectionEnabled=False)
    identifier = created["identifier"]
    ctx.on_cleanup(lambda: _best_effort_delete(dsql, identifier))

    _poll_until(
        lambda: dsql.get_cluster(identifier=identifier)["status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=300.0,
        interval_s=5.0,
    )

    delete_resp = dsql.delete_cluster(identifier=identifier)
    assert delete_resp["identifier"] == identifier, (
        f"delete_cluster echoed identifier={delete_resp['identifier']!r}, expected {identifier!r}"
    )
    assert delete_resp["status"] in ("DELETING", "DELETED"), (
        f"expected delete_cluster status in (DELETING, DELETED), got {delete_resp['status']!r}"
    )

    def _probe():
        try:
            return dsql.get_cluster(identifier=identifier)["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return "DELETED"
            raise

    final_status = _poll_until(_probe, lambda s: s == "DELETED", timeout_s=300.0, interval_s=5.0)
    assert final_status == "DELETED", f"expected GetCluster to report DELETED, got {final_status!r}"

    code, message = _error(lambda: dsql.delete_cluster(identifier=identifier))
    assert code == "ResourceNotFoundException", (
        f"re-deleting the gone cluster should raise ResourceNotFoundException, got {code!r}"
    )
    assert message == (
        f"The resource with ARN {created["arn"]} doesn't exist. Verify the ARN and try again."
    ), message


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    """Call fn() and return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _best_effort_delete(dsql, identifier):
    try:
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
