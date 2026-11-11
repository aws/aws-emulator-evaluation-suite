"""apply-pending-maintenance-action-missing-apply-on-rejected."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apply-pending-maintenance-action-missing-apply-on-rejected"
GROUP = "overly-permissive"
SERVICES = ["docdb-elastic"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ApplyPendingMaintenanceAction with optInType=APPLY_ON but no applyOn date is
    rejected with ValidationException and creates no pending-action opt-in record; the
    read-side maintenance APIs on the same resource still function (control)."""
    docdb = ctx.client("docdb-elastic")
    arn = _create_cluster(ctx)["clusterArn"]
    _register_cluster_cleanup(ctx, arn)
    _wait_for_cluster_status(ctx, arn, {"ACTIVE"})

    code, message = _error_code(
        lambda: docdb.apply_pending_maintenance_action(
            resourceArn=arn, applyAction="ENGINE_UPDATE", optInType="APPLY_ON"
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "ApplyOn is required when OptInType is APPLY_ON"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: GetPendingMaintenanceAction on a resource with no pending action does
    # NOT raise ResourceNotFoundException — it returns 200 with
    # an empty pendingMaintenanceActionDetails list.
    pending = docdb.get_pending_maintenance_action(resourceArn=arn)["resourcePendingMaintenanceAction"]
    assert pending["pendingMaintenanceActionDetails"] == [], (
        f"expected no pending maintenance action to be recorded, got "
        f"{pending['pendingMaintenanceActionDetails']!r}"
    )

    # Positive control: the read-side maintenance APIs still succeed for a live resource.
    listing = docdb.list_pending_maintenance_actions()
    assert "resourcePendingMaintenanceActions" in listing, (
        f"expected list_pending_maintenance_actions to return a resourcePendingMaintenanceActions "
        f"key, got keys {sorted(listing)!r}"
    )
    get_cluster_still_works = docdb.get_cluster(clusterArn=arn)["cluster"]
    assert get_cluster_still_works["status"] == "ACTIVE", (
        f"expected cluster to remain ACTIVE after the rejected call, "
        f"got {get_cluster_still_works['status']!r}"
    )


# ===== helpers =====
def _admin_password(ctx):
    suffix = re.sub(r"[^A-Za-z0-9]", "", ctx.unique_name("x"))[:12]
    return f"S1mparityPw{suffix}"


def _create_cluster(ctx, **overrides):
    docdb = ctx.client("docdb-elastic")
    params = {
        "clusterName": ctx.unique_name("sim2real-docdbe-"),
        "authType": "PLAIN_TEXT",
        "adminUserName": "sim2realadmin",
        "adminUserPassword": _admin_password(ctx),
        "shardCapacity": 2,
        "shardCount": 1,
    }
    params.update(overrides)
    return docdb.create_cluster(**params)["cluster"]


def _error_code(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected success
    raises, so a target accepting what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


_TRANSIENT_STATUSES = {
    "CREATING", "STARTING", "STOPPING", "UPDATING", "DELETING",
    "MERGING", "MODIFYING", "SPLITTING", "COPYING", "MAINTENANCE",
}


def _wait_for_cluster_status(ctx, arn, targets, timeout_s=1800.0, interval_s=15.0):
    docdb = ctx.client("docdb-elastic")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = docdb.get_cluster(clusterArn=arn)["cluster"]
        if last["status"] in targets:
            return last
        if last["status"] not in _TRANSIENT_STATUSES:
            raise AssertionError(
                f"cluster {arn} reached unexpected terminal status {last['status']!r} "
                f"while waiting for {targets}"
            )
        time.sleep(interval_s)
    raise AssertionError(
        f"cluster {arn} did not reach {targets} within {timeout_s}s "
        f"(last status={last['status'] if last else None})"
    )


def _register_cluster_cleanup(ctx, arn):
    def _cleanup():
        docdb = ctx.client("docdb-elastic")
        # fits the suite's 900 s cleanup budget
        deadline = time.monotonic() + 840.0
        while time.monotonic() < deadline:
            try:
                docdb.delete_cluster(clusterArn=arn)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code == "ConflictException":
                    try:
                        status = docdb.get_cluster(clusterArn=arn)["cluster"]["status"]
                    except ClientError as err:
                        if err.response["Error"]["Code"] != "ResourceNotFoundException":
                            raise
                        return
                    if status == "STOPPED":
                        try:
                            docdb.start_cluster(clusterArn=arn)
                        except ClientError as err:
                            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                                raise
                    time.sleep(2.0)
                    continue
                raise
        raise AssertionError(f"cluster {arn} still refused DeleteCluster after 840 s")

    ctx.on_cleanup(_cleanup)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
