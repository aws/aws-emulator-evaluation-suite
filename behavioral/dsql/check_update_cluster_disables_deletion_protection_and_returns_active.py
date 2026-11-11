"""update-cluster-disables-deletion-protection-and-returns-active."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-cluster-disables-deletion-protection-and-returns-active"
GROUP = "state"
SERVICES = ["dsql"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCluster toggling deletionProtectionEnabled persists and the cluster settles back to ACTIVE."""
    dsql = ctx.client("dsql")
    # deletionProtectionEnabled defaults to true, so this cluster starts protected.
    created = dsql.create_cluster(
        tags={"sim2real-created-with": "update-cluster-disables-deletion-protection-and-returns-active"}
    )
    identifier = created["identifier"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, identifier))
    assert created["deletionProtectionEnabled"] is True, (
        f"expected CreateCluster to default deletionProtectionEnabled to True, got "
        f"{created['deletionProtectionEnabled']!r}"
    )

    _poll_until(
        lambda: dsql.get_cluster(identifier=identifier)["status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=300.0,
        interval_s=5.0,
    )

    update_resp = dsql.update_cluster(identifier=identifier, deletionProtectionEnabled=False)
    assert update_resp["identifier"] == identifier, (
        f"expected UpdateCluster to echo identifier {identifier!r}, got {update_resp['identifier']!r}"
    )
    assert update_resp["status"] in ("UPDATING", "ACTIVE"), (
        f"expected UpdateCluster response status in (UPDATING, ACTIVE), got {update_resp['status']!r}"
    )

    final = _poll_until(
        lambda: dsql.get_cluster(identifier=identifier),
        lambda r: r["status"] in ("ACTIVE", "FAILED"),
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert final["status"] == "ACTIVE", f"cluster ended in {final['status']!r} after update"
    assert final["deletionProtectionEnabled"] is False, "deletionProtectionEnabled did not persist as disabled"


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


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
