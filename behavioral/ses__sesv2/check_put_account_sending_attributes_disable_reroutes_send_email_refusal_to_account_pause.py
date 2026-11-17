"""put-account-sending-attributes-disable-reroutes-send-email-refusal-to-account-pause."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-account-sending-attributes-disable-reroutes-send-email-refusal-to-account-pause"
GROUP = "shared-state-v1-v2"
SERVICES = ["ses", "sesv2"]

_RECIPIENT = "success@simulator.amazonses.com"


def expect_error(fn, code: str, message: str) -> None:
    try:
        result = fn()
    except ClientError as exc:
        err = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
        assert err == (code, message), f"expected {(code, message)!r}, got {err!r}"
        return
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: not reached within {timeout_s}s; last observation {value!r}"
            )
        time.sleep(interval_s)
        value = probe()
    return value


def _poll_refusal(fn, code: str, message: str, *, timeout_s: float, interval_s: float, description: str) -> None:
    """Retry ``expect_error`` until it stops raising, or re-raise its last AssertionError."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            expect_error(fn, code, message)
            return
        except AssertionError as exc:
            if time.monotonic() >= deadline:
                raise AssertionError(f"{description}: not reached within {timeout_s}s ({exc})") from exc
            time.sleep(interval_s)


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
    "resource:account-singleton:ses-account",
)
def run(ctx) -> None:
    """SESv2 PutAccountSendingAttributes(SendingEnabled=False) changes the SES v1 SendEmail
    refusal for the same unverified source from MessageRejected to AccountSendingPausedException;
    re-enabling through v2 reverts it, both exact messages, with the shared flag visible via v1."""
    v1 = ctx.client("ses")
    v2 = ctx.client("sesv2")

    sender = f"noreply@{ctx.unique_name('sim2real-behav-v2pause-')}.example.com"

    def _send() -> None:
        v1.send_email(
            Source=sender,
            Destination={"ToAddresses": [_RECIPIENT]},
            Message={
                "Subject": {"Data": "sim2real v2 account-pause probe"},
                "Body": {"Text": {"Data": "this send must be refused"}},
            },
        )

    identity_refusal = (
        f"Email address is not verified. The following identities failed the check in region "
        f"{ctx.region.upper()}: {sender}"
    )
    _IDENTITY_GATE = ("MessageRejected", identity_refusal)
    _ACCOUNT_PAUSE = ("AccountSendingPausedException", "Sending is paused for this account.")

    # --- Setup: read the account-wide flag first, so cleanup restores exactly what it found.
    original_enabled = v2.get_account()["SendingEnabled"]
    assert original_enabled is True, (
        f"setup precondition: account-level sending must start ENABLED, or the baseline below "
        f"measures the paused state and the whole comparison inverts; GetAccount reported "
        f"SendingEnabled={original_enabled!r}"
    )
    ctx.on_cleanup(lambda: v2.put_account_sending_attributes(SendingEnabled=True))

    # --- Control: with sending enabled, the unverified source is refused by the identity gate.
    #     This same send is what proves the account pause (not a broken sender) causes the later
    #     change, and what the restored call must match again after re-enabling.
    expect_error(_send, *_IDENTITY_GATE)

    # --- Break exactly one thing, through the v2 write.
    v2.put_account_sending_attributes(SendingEnabled=False)
    paused_flag = _poll(
        lambda: v2.get_account()["SendingEnabled"],
        lambda v: v is False,
        timeout_s=60,
        interval_s=2,
        description="SESv2 GetAccount reflects SendingEnabled=False after the v2 disable",
    )
    assert paused_flag is False, f"expected SendingEnabled False, got {paused_flag!r}"

    # --- Read the same flag through the v1 surface: the account-wide state is shared, not a
    #     copy private to the API that wrote it.
    v1_paused_flag = v1.get_account_sending_enabled()["Enabled"]
    assert v1_paused_flag is False, (
        f"the v2 disable must be visible through the v1 GetAccountSendingEnabled read on the "
        f"same shared account flag; expected False, got {v1_paused_flag!r}"
    )

    # --- The v1 data-plane call now answers the account-pause refusal instead of the identity
    #     gate, for the identical send.
    _poll_refusal(
        _send,
        *_ACCOUNT_PAUSE,
        timeout_s=60,
        interval_s=5,
        description="SendEmail answers the account-pause refusal once the v2 disable reaches the API front door",
    )

    # --- Restore through the v2 write and prove the revert on both the control plane and the
    #     v1 data-plane refusal.
    v2.put_account_sending_attributes(SendingEnabled=True)
    restored_flag = _poll(
        lambda: v2.get_account()["SendingEnabled"],
        lambda v: v is True,
        timeout_s=60,
        interval_s=2,
        description="SESv2 GetAccount reflects SendingEnabled=True after the v2 re-enable",
    )
    assert restored_flag is True, f"expected SendingEnabled True, got {restored_flag!r}"

    v1_restored_flag = v1.get_account_sending_enabled()["Enabled"]
    assert v1_restored_flag is True, (
        f"the v2 re-enable must be visible through the v1 GetAccountSendingEnabled read; "
        f"expected True, got {v1_restored_flag!r}"
    )

    _poll_refusal(
        _send,
        *_IDENTITY_GATE,
        timeout_s=60,
        interval_s=5,
        description="SendEmail reverts to the identity-gate refusal once the v2 re-enable reaches the API front door",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
