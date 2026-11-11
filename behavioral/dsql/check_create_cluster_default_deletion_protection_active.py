"""create-cluster-default-deletion-protection-active."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-cluster-default-deletion-protection-active"
GROUP = "state"
SERVICES = ["dsql"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCluster with no explicit deletionProtectionEnabled defaults it to True (per the
    Smithy model default) and the cluster transitions CREATING -> ACTIVE with an endpoint."""
    dsql = ctx.client("dsql")
    created = dsql.create_cluster(
        tags={
            "sim2real-created-with": "create-cluster-default-deletion-protection-active",
            "sim2real-purpose": "behavioral-test",
        }
    )
    identifier = created["identifier"]
    ctx.on_cleanup(lambda: _delete_with_protection_disabled(ctx, dsql, identifier))

    assert created["deletionProtectionEnabled"] is True, (
        "deletionProtectionEnabled should default to True when omitted from CreateCluster"
    )
    assert re.match(r"^[a-z0-9]{26}$", identifier), f"unexpected identifier shape: {identifier!r}"
    assert created["arn"].endswith(identifier), (
        f"arn {created['arn']!r} does not end with identifier {identifier!r}"
    )

    final = _wait_for_status(ctx, dsql, identifier, {"ACTIVE"}, timeout_s=180)
    assert final["status"] == "ACTIVE", f"expected ACTIVE, got {final['status']!r}"
    assert final["deletionProtectionEnabled"] is True, (
        "deletionProtectionEnabled should still be True on the ACTIVE cluster"
    )
    assert final.get("endpoint"), "ACTIVE cluster must expose a connection endpoint"


def _wait_for_status(ctx, dsql, identifier, target_statuses, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = dsql.get_cluster(identifier=identifier)
        if last["status"] in target_statuses:
            return last
        if last["status"] == "FAILED" and "FAILED" not in target_statuses:
            raise AssertionError(f"cluster {identifier} unexpectedly reached FAILED")
        time.sleep(interval_s)
    raise AssertionError(
        f"cluster {identifier} never reached {target_statuses}, last status={last and last.get('status')}"
    )


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
