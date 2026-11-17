"""account-sending-switch-is-shared-between-v1-and-v2."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "account-sending-switch-is-shared-between-v1-and-v2"
GROUP = "account"
SERVICES = ["ses", "sesv2"]


def _poll(probe, predicate, *, timeout_s, interval_s=2.0, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "plane:control",
    "resource:account-singleton:ses-account",
)
def run(ctx) -> None:
    """The account-wide sending switch is one piece of state: ses UpdateAccountSendingEnabled is
    visible through sesv2 GetAccount, and sesv2 PutAccountSendingAttributes is visible through ses
    GetAccountSendingEnabled."""
    ses = ctx.client("ses")
    sesv2 = ctx.client("sesv2")

    original_v1 = ses.get_account_sending_enabled()["Enabled"]
    original_v2 = sesv2.get_account()["SendingEnabled"]
    assert original_v1 == original_v2, (
        f"GetAccountSendingEnabled reported Enabled={original_v1!r} while GetAccount reported "
        f"SendingEnabled={original_v2!r} for what must be the same account-level switch"
    )

    flipped = not original_v1
    ses.update_account_sending_enabled(Enabled=flipped)
    # Restore the switch no matter where the body stops; the in-line v2 restore below makes
    # this a no-op on the success path.
    ctx.on_cleanup(lambda: sesv2.put_account_sending_attributes(SendingEnabled=original_v1))

    seen_via_v2 = _poll(
        lambda: sesv2.get_account()["SendingEnabled"],
        lambda v: v == flipped,
        timeout_s=30,
        description="GetAccount SendingEnabled reflecting ses.update_account_sending_enabled",
    )
    assert seen_via_v2 == flipped, (
        f"after ses.update_account_sending_enabled(Enabled={flipped!r}), sesv2.get_account() "
        f"reported SendingEnabled={seen_via_v2!r}"
    )

    sesv2.put_account_sending_attributes(SendingEnabled=original_v1)

    seen_via_v1 = _poll(
        lambda: ses.get_account_sending_enabled()["Enabled"],
        lambda v: v == original_v1,
        timeout_s=30,
        description="GetAccountSendingEnabled reflecting sesv2.put_account_sending_attributes",
    )
    assert seen_via_v1 == original_v1, (
        f"after sesv2.put_account_sending_attributes(SendingEnabled={original_v1!r}), "
        f"ses.get_account_sending_enabled() reported Enabled={seen_via_v1!r}"
    )

    restored_v2 = sesv2.get_account()["SendingEnabled"]
    assert restored_v2 == original_v1, (
        f"GetAccount SendingEnabled did not settle on {original_v1!r} after the restore, got "
        f"{restored_v2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
