"""sts-preferences-update-persists."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "sts-preferences-update-persists"
GROUP = "server-side"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:sts-token-preferences")
def run(ctx) -> None:
    """SetSecurityTokenServicePreferences durably changes the account's global STS token
    endpoint version, reflected as an integer (1 or 2) in GetAccountSummary's
    GlobalEndpointTokenVersion, and the change is enforced server-side (round-trips exactly)."""
    iam = ctx.client("iam")

    initial = iam.get_account_summary()["SummaryMap"]["GlobalEndpointTokenVersion"]
    assert initial in (1, 2), (
        f"GetAccountSummary.SummaryMap.GlobalEndpointTokenVersion must be 1 or 2, got {initial!r}"
    )
    flipped_token, flipped_value = ("v1Token", 1) if initial == 2 else ("v2Token", 2)
    original_token = "v1Token" if initial == 1 else "v2Token"
    ctx.on_cleanup(lambda: iam.set_security_token_service_preferences(
        GlobalEndpointTokenVersion=original_token))

    iam.set_security_token_service_preferences(GlobalEndpointTokenVersion=flipped_token)
    after = _poll_until(
        lambda: iam.get_account_summary()["SummaryMap"]["GlobalEndpointTokenVersion"],
        lambda v: v == flipped_value,
        timeout_s=30.0,
        description=f"GlobalEndpointTokenVersion to become {flipped_value} after Set({flipped_token})",
    )
    assert after == flipped_value, (
        f"expected GlobalEndpointTokenVersion == {flipped_value} after Set({flipped_token}), "
        f"got {after!r}"
    )

    iam.set_security_token_service_preferences(GlobalEndpointTokenVersion=original_token)
    restored = _poll_until(
        lambda: iam.get_account_summary()["SummaryMap"]["GlobalEndpointTokenVersion"],
        lambda v: v == initial,
        timeout_s=30.0,
        description=f"GlobalEndpointTokenVersion to be restored to {initial} after Set({original_token})",
    )
    assert restored == initial, (
        f"expected GlobalEndpointTokenVersion == {initial} after Set({original_token}) "
        f"(restore), got {restored!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.5, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"timed out after {timeout_s}s waiting for {description}, last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
