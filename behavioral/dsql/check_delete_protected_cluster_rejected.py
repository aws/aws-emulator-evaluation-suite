"""delete-protected-cluster-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-protected-cluster-rejected"
GROUP = "overly-permissive"
SERVICES = ["dsql"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCluster on a cluster with deletionProtectionEnabled=True fails with ValidationException and
    AWS's exact message and leaves the cluster in place; after protection is disabled, the same call
    moves it to DELETING or DELETED."""
    dsql = ctx.client("dsql")
    created = dsql.create_cluster(deletionProtectionEnabled=True)
    identifier = created["identifier"]
    ctx.on_cleanup(lambda: _delete_with_protection_disabled(dsql, identifier))
    _wait_for_status(dsql, identifier, {"ACTIVE"}, timeout_s=180)

    code, message = _error(lambda: dsql.delete_cluster(identifier=identifier))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "Can't delete cluster: Deletion protection is enabled. To proceed, disable deletion protection and try again.", message

    # effect absent: the cluster is still there, untouched
    still_there = dsql.get_cluster(identifier=identifier)
    assert still_there["status"] not in ("DELETING", "DELETED"), (
        f"expected status outside (DELETING, DELETED), got {still_there['status']!r}"
    )
    assert still_there["deletionProtectionEnabled"] is True, (
        f"expected deletionProtectionEnabled=True, got {still_there['deletionProtectionEnabled']!r}"
    )

    # positive control: disable protection, then the identical delete call succeeds
    dsql.update_cluster(identifier=identifier, deletionProtectionEnabled=False)
    _wait_for_status(dsql, identifier, {"ACTIVE"}, timeout_s=180)
    dsql.delete_cluster(identifier=identifier)

    # terminal read: independent of the mutating delete_cluster call above
    after_delete = _read_status_allow_gone(dsql, identifier)
    assert after_delete in ("DELETING", "DELETED"), (
        f"expected status in (DELETING, DELETED) after the restored delete, got {after_delete!r}"
    )


def _error(fn):
    """Call fn() and return its ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _read_status_allow_gone(dsql, identifier):
    from botocore.exceptions import ClientError

    try:
        return dsql.get_cluster(identifier=identifier)["status"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return "DELETED"
        raise


def _wait_for_status(dsql, identifier, target_statuses, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = dsql.get_cluster(identifier=identifier)
        if last["status"] in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"cluster never reached {target_statuses}, last={last}")


def _delete_with_protection_disabled(dsql, identifier):
    from botocore.exceptions import ClientError

    try:
        dsql.update_cluster(identifier=identifier, deletionProtectionEnabled=False)
        _wait_for_status(dsql, identifier, {"ACTIVE", "IDLE", "INACTIVE"}, timeout_s=120)
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
