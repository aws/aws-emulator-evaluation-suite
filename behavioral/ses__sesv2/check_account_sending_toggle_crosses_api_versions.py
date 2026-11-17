"""account-sending-toggle-crosses-api-versions."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "account-sending-toggle-crosses-api-versions"
GROUP = "account"
SERVICES = ["ses", "sesv2"]


def _settle(read, is_done, *, budget_s=30.0, step_s=1.0, label="value"):
    """Call read() until is_done(result) holds; return it, or raise with the last read."""
    deadline = time.monotonic() + budget_s
    last = None
    while time.monotonic() < deadline:
        last = read()
        if is_done(last):
            return last
        time.sleep(step_s)
    raise AssertionError(f"{label} never settled within {budget_s}s; last saw {last!r}")


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "plane:control",
    "resource:account-singleton:ses-account",
)
def run(ctx) -> None:
    """A v2 PutAccountSendingAttributes write flips the one account-wide sending flag that v1
    GetAccountSendingEnabled reads, and a v1 UpdateAccountSendingEnabled write flips the same
    flag back, visible through v2 GetAccount.SendingEnabled; the original value is restored.
    """
    v1 = ctx.client("ses")
    v2 = ctx.client("sesv2")

    original = v1.get_account_sending_enabled()["Enabled"]
    flipped = not original
    ctx.on_cleanup(lambda: v1.update_account_sending_enabled(Enabled=original))

    v2.put_account_sending_attributes(SendingEnabled=flipped)
    via_v1 = _settle(
        lambda: v1.get_account_sending_enabled()["Enabled"],
        lambda v: v == flipped,
        label="GetAccountSendingEnabled picking up the v2 PutAccountSendingAttributes write",
    )
    assert via_v1 == flipped, (
        f"v1 GetAccountSendingEnabled reports {via_v1!r} after v2 set SendingEnabled={flipped!r}"
    )

    v1.update_account_sending_enabled(Enabled=original)
    via_v2 = _settle(
        lambda: v2.get_account()["SendingEnabled"],
        lambda v: v == original,
        label="GetAccount picking up the v1 UpdateAccountSendingEnabled write",
    )
    assert via_v2 == original, (
        f"v2 GetAccount reports SendingEnabled={via_v2!r} after v1 restored Enabled={original!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
