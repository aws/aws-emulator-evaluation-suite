"""update-cluster-toggles-deletion-protection."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-cluster-toggles-deletion-protection"
GROUP = "state"
SERVICES = ["dsql"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCluster flips deletionProtectionEnabled, the cluster transitions through UPDATING
    back to ACTIVE, and GetCluster reflects the new persisted value."""
    dsql = ctx.client("dsql")
    created = dsql.create_cluster(
        deletionProtectionEnabled=False,
        tags={"sim2real-created-with": "create-cluster", "sim2real-purpose": "behavioral-test"},
    )
    identifier = created["identifier"]
    ctx.on_cleanup(lambda: _delete_with_protection_disabled(ctx, dsql, identifier))

    _wait_for_status(ctx, dsql, identifier, {"ACTIVE"}, timeout_s=180)
    initial = dsql.get_cluster(identifier=identifier)["deletionProtectionEnabled"]
    assert initial is False, f"expected deletionProtectionEnabled=False after create, got {initial!r}"

    dsql.update_cluster(identifier=identifier, deletionProtectionEnabled=True)
    final = _wait_for_status(ctx, dsql, identifier, {"ACTIVE"}, timeout_s=180)
    assert final["deletionProtectionEnabled"] is True, (
        "GetCluster must reflect the deletionProtectionEnabled value set via UpdateCluster"
    )


def _wait_for_status(ctx, dsql, identifier, target_statuses, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = dsql.get_cluster(identifier=identifier)
        if last["status"] in target_statuses:
            return last
        if last["status"] == "FAILED" and "FAILED" not in target_statuses:
            raise AssertionError(f"cluster unexpectedly reached FAILED: {last}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster never reached {target_statuses}, last={last}")


def _delete_with_protection_disabled(ctx, dsql, identifier):
    from botocore.exceptions import ClientError

    try:
        dsql.update_cluster(identifier=identifier, deletionProtectionEnabled=False)
        _wait_for_status(ctx, dsql, identifier, {"ACTIVE", "IDLE", "INACTIVE"}, timeout_s=120)
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
