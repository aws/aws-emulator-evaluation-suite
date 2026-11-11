"""account-sending-enabled-toggle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "account-sending-enabled-toggle"
GROUP = 'sending'
SERVICES = ['ses']

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ses-account")
def run(ctx) -> None:
    """UpdateAccountSendingEnabled flips account-wide sending state observable via GetAccountSendingEnabled, and restores."""
    ses = ctx.client("ses")
    original = ses.get_account_sending_enabled().get("Enabled", True)
    # Global, account-wide mutation: always restore sending on cleanup as a safety net in
    # addition to the explicit restore below, in case the body is killed partway through.
    ctx.on_cleanup(lambda: ses.update_account_sending_enabled(Enabled=original))
    try:
        ses.update_account_sending_enabled(Enabled=False)
        disabled = _poll_until(
            lambda: ses.get_account_sending_enabled().get("Enabled"),
            lambda v: v is False,
            timeout_s=30,
            interval_s=2.0,
            description="GetAccountSendingEnabled == False",
        )
        assert disabled is False, "GetAccountSendingEnabled did not reflect the disabled state"

        # Idempotent re-disable must not error nor flip the state back.
        ses.update_account_sending_enabled(Enabled=False)
        assert ses.get_account_sending_enabled().get("Enabled") is False, (
            "repeating UpdateAccountSendingEnabled(False) changed the state"
        )
    finally:
        ses.update_account_sending_enabled(Enabled=original)

    restored = _poll_until(
        lambda: ses.get_account_sending_enabled().get("Enabled"),
        lambda v: v == original,
        timeout_s=30,
        interval_s=2.0,
        description="account sending state restored",
    )
    assert restored == original, "account sending state not restored after re-enabling"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
