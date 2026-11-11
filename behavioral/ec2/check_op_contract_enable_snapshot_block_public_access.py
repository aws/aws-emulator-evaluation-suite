"""op-contract-enableSnapshotBlockPublicAccess."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-enableSnapshotBlockPublicAccess"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ebs-snapshot-block-public-access")
def run(ctx) -> None:
    """EnableSnapshotBlockPublicAccess: account-level setting contract + DryRun error
    boundary."""
    ec2 = ctx.client("ec2")

    original_state = ec2.get_snapshot_block_public_access_state()["State"]

    def _restore():
        if original_state == "unblocked":
            ec2.disable_snapshot_block_public_access()
        else:
            ec2.enable_snapshot_block_public_access(State=original_state)

    ctx.on_cleanup(_restore)

    resp = ec2.enable_snapshot_block_public_access(State="block-new-sharing")
    assert resp["State"] == "block-new-sharing", f"expected echoed State block-new-sharing, got {resp['State']!r}"

    # Independent read: the account-level setting must actually converge to what we just
    # requested, not merely echo the request back. Documented as taking up to ~10 minutes to
    # propagate, but it usually converges in well under a minute, so a bounded
    # poll that raises on timeout is enough.
    converged = _poll_until(
        lambda: ec2.get_snapshot_block_public_access_state()["State"],
        lambda s: s == "block-new-sharing",
        timeout_s=60,
        interval_s=5,
        description="EnableSnapshotBlockPublicAccess convergence to block-new-sharing",
    )
    assert converged == "block-new-sharing", f"expected converged state block-new-sharing, got {converged!r}"

    code, message, _ = _client_error(
        lambda: ec2.enable_snapshot_block_public_access(State="block-all-sharing", DryRun=True)
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == "Request would have succeeded, but DryRun flag is set.", f"unexpected DryRunOperation message: {message!r}"

    # DryRun must not have advanced state past what we already converged on above.
    still_after = ec2.get_snapshot_block_public_access_state()["State"]
    assert still_after == "block-new-sharing", f"DryRun mutated state to {still_after!r}"


def _client_error(fn):
    """Call fn() and return (code, message, http_status) of the ClientError it raises.
    An unexpected success raises AssertionError rather than returning a falsy value."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message"), exc.response["ResponseMetadata"]["HTTPStatusCode"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 3.0,
    description: str = "condition",
) -> Any:
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {value!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
