"""storage-tier-policy-lifecycle-transitions."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "storage-tier-policy-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:logs-storage-tier-policy")
def run(ctx) -> None:
    """PutStorageTierPolicy sets an account-level Infrequent Access (INTELLIGENT_TIERING)
    tier policy that GetStorageTierPolicy reflects immediately, restoring the account's
    original policy afterward."""
    logs = ctx.client("logs")

    original = logs.get_storage_tier_policy().get("storageTier", "STANDARD")
    ctx.on_cleanup(lambda: logs.put_storage_tier_policy(storageTier=original))

    target = "INTELLIGENT_TIERING" if original != "INTELLIGENT_TIERING" else "STANDARD"

    put_resp = logs.put_storage_tier_policy(storageTier=target)
    assert put_resp["storageTier"] == target, (
        f"PutStorageTierPolicy({target!r}) echoed storageTier={put_resp.get('storageTier')!r}"
    )

    got = _poll_until(
        lambda: logs.get_storage_tier_policy(),
        lambda r: r.get("storageTier") == target,
        timeout_s=30.0,
    )
    assert got["storageTier"] == target, (
        f"GetStorageTierPolicy never reflected {target!r} within 30s, last saw {got.get('storageTier')!r}"
    )
    assert "lastUpdatedTime" in got, f"GetStorageTierPolicy response missing lastUpdatedTime: {got!r}"

    # flip back to the other value to prove the setter is not a one-way switch
    other = "STANDARD" if target == "INTELLIGENT_TIERING" else "INTELLIGENT_TIERING"
    logs.put_storage_tier_policy(storageTier=other)
    got2 = _poll_until(
        lambda: logs.get_storage_tier_policy(),
        lambda r: r.get("storageTier") == other,
        timeout_s=30.0,
    )
    assert got2["storageTier"] == other, (
        f"GetStorageTierPolicy never reflected the reverse transition to {other!r} within 30s, "
        f"last saw {got2.get('storageTier')!r}"
    )


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float = 60.0, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
