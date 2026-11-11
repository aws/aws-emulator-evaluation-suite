"""create-cluster-creating-to-active-transition."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-cluster-creating-to-active-transition"
GROUP = "state"
SERVICES = ["dsql"]

_ID_RE = re.compile(r"^[a-z0-9]{26}$")
_ARN_RE = re.compile(r"^arn:aws(-[^:]+)?:dsql:[a-z0-9-]{1,20}:[0-9]{12}:cluster/[a-z0-9]{26}$")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCluster starts a cluster in CREATING (or already ACTIVE) and it settles to ACTIVE."""
    dsql = ctx.client("dsql")
    resp = dsql.create_cluster(
        deletionProtectionEnabled=False,
        tags={"sim2real-purpose": "creating-to-active-transition"},
    )
    identifier = resp["identifier"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, identifier))

    assert _ID_RE.match(identifier), f"unexpected identifier shape: {identifier!r}"
    assert _ARN_RE.match(resp["arn"]), f"unexpected arn shape: {resp['arn']!r}"
    assert resp["status"] in ("CREATING", "ACTIVE"), resp["status"]

    final = _poll_until(
        lambda: dsql.get_cluster(identifier=identifier),
        lambda r: r["status"] in ("ACTIVE", "FAILED"),
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert final["status"] == "ACTIVE", f"cluster reached terminal status {final['status']!r} instead of ACTIVE"
    assert final["identifier"] == identifier, f"expected identifier {identifier!r}, got {final['identifier']!r}"
    assert final["arn"] == resp["arn"], f"expected arn {resp['arn']!r}, got {final['arn']!r}"


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
