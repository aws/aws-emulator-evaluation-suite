"""automated-discovery-configuration-enable-disable-cycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "automated-discovery-configuration-enable-disable-cycle"
GROUP = "state"
SERVICES = ["macie2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:macie")
def run(ctx) -> None:
    """UpdateAutomatedDiscoveryConfiguration toggles the account-wide status in both directions and
    each transition is observable through an independent read."""
    _ensure_macie_enabled(ctx)
    macie = ctx.client("macie2")
    original_status = macie.get_automated_discovery_configuration()["status"]
    other = "DISABLED" if original_status == "ENABLED" else "ENABLED"
    ctx.on_cleanup(lambda: macie.update_automated_discovery_configuration(status=original_status))

    macie.update_automated_discovery_configuration(status=other)
    observed = _poll_until(
        lambda: macie.get_automated_discovery_configuration()["status"],
        lambda s: s == other,
        timeout_s=60,
    )
    assert observed == other, f"expected status {other} after toggling away from {original_status}, got {observed}"

    macie.update_automated_discovery_configuration(status=original_status)
    restored = _poll_until(
        lambda: macie.get_automated_discovery_configuration()["status"],
        lambda s: s == original_status,
        timeout_s=60,
    )
    assert restored == original_status, f"expected status {original_status} after restoring, got {restored}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _ensure_macie_enabled(ctx) -> None:
    from botocore.exceptions import ClientError

    macie = ctx.client("macie2")
    try:
        macie.get_macie_session()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code not in ("ResourceNotFoundException", "AccessDeniedException"):
            raise
        try:
            macie.enable_macie()
        except ClientError as exc2:
            if exc2.response["Error"]["Code"] != "ConflictException":
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
