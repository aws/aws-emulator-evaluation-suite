"""delete-cluster-deletion-protection-conflict-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-cluster-deletion-protection-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["dsql"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCluster on a deletion-protected cluster is rejected (empirically ValidationException, not
    ConflictException), the cluster remains fully intact, and after disabling protection on that SAME
    cluster the identical DeleteCluster call succeeds."""
    dsql = ctx.client("dsql")

    protected = dsql.create_cluster(deletionProtectionEnabled=True)
    protected_id = protected["identifier"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, protected_id))
    _poll_until(
        lambda: dsql.get_cluster(identifier=protected_id)["status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=300.0,
        interval_s=5.0,
    )

    code, message = _error(lambda: dsql.delete_cluster(identifier=protected_id))
    assert code == "ValidationException", code
    assert message == "Can't delete cluster: Deletion protection is enabled. To proceed, disable deletion protection and try again.", message

    # Effect absent: the cluster is untouched and still reachable/ACTIVE.
    still_there = dsql.get_cluster(identifier=protected_id)
    assert still_there["status"] == "ACTIVE"
    assert still_there["deletionProtectionEnabled"] is True

    # Positive control: an otherwise-identical unprotected cluster CAN be deleted, confirmed by an
    # independent read rather than trusting the mutating call's own response.
    control = dsql.create_cluster(deletionProtectionEnabled=False)
    control_id = control["identifier"]
    _poll_until(
        lambda: dsql.get_cluster(identifier=control_id)["status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=300.0,
        interval_s=5.0,
    )
    dsql.delete_cluster(identifier=control_id)
    _assert_deleted_or_deleting(dsql, control_id, control["arn"])

    # Restore: disabling protection on the SAME cluster that was rejected above must make the
    # identical DeleteCluster call succeed -- proven via an independent read, not the mutating
    # call's own response.
    dsql.update_cluster(identifier=protected_id, deletionProtectionEnabled=False)
    _poll_until(
        lambda: dsql.get_cluster(identifier=protected_id)["status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=300.0,
        interval_s=5.0,
    )
    dsql.delete_cluster(identifier=protected_id)
    _assert_deleted_or_deleting(dsql, protected_id, protected["arn"])


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
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _assert_deleted_or_deleting(dsql, identifier, arn):
    from botocore.exceptions import ClientError

    try:
        after = dsql.get_cluster(identifier=identifier)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", code
        message = exc.response["Error"].get("Message")
        assert message == f"The resource with ARN {arn} doesn't exist. Verify the ARN and try again.", message
        return
    assert after["status"] in ("DELETING", "DELETED"), after["status"]


def _delete_cluster(ctx, identifier):
    from botocore.exceptions import ClientError

    dsql = ctx.client("dsql")
    try:
        dsql.update_cluster(identifier=identifier, deletionProtectionEnabled=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
