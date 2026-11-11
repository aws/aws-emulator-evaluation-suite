"""send-email-unverified-source-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-email-unverified-source-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ses']

def _unique_email(ctx, prefix="probe-"):
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}@example.com"


def _verification_status(ses, identity):
    entry = ses.get_identity_verification_attributes(
        Identities=[identity]
    ).get("VerificationAttributes", {}).get(identity)
    return entry.get("VerificationStatus") if entry else None


# The refusal a send meets while the account's sending is paused, per API.
_PAUSED_CODE = {"ses": "AccountSendingPausedException", "sesv2": "SendingPausedException"}


def _send_refusal(ctx, api: str, send, own_code: str):
    """Run ``send`` between two GetAccountSendingEnabled reads; return its ClientError (None on
    success) and the codes it may carry: ``own_code`` while sending is enabled, the paused refusal
    while it is paused, and either when the state changes in between."""
    account = ctx.client("ses")
    before = account.get_account_sending_enabled()["Enabled"]
    try:
        send()
        err = None
    except ClientError as exc:
        err = exc
    after = account.get_account_sending_enabled()["Enabled"]
    return err, {own_code if enabled else _PAUSED_CODE[api] for enabled in (before, after)}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendEmail from an unverified identity is rejected with MessageRejected naming that identity,
    without counting a send or verifying the sender as a side effect."""
    ses = ctx.client("ses")
    email = _unique_email(ctx)
    ses.verify_email_identity(EmailAddress=email)
    ctx.on_cleanup(lambda _n=email: ses.delete_identity(Identity=_n))

    status = _verification_status(ses, email)
    assert status == "Pending", (
        f"precondition: a freshly requested email identity should be Pending, got {status!r}"
    )

    # No successful-send control: verifying a fresh identity needs a real mailbox click-through.
    sent_before = ses.get_send_quota()["SentLast24Hours"]

    exc, allowed = _send_refusal(
        ctx,
        "ses",
        lambda: ses.send_email(
            Source=email,
            Destination={"ToAddresses": [email]},
            Message={"Subject": {"Data": "probe"}, "Body": {"Text": {"Data": "probe body"}}},
        ),
        "MessageRejected",
    )
    assert exc is not None, "expected the send to be refused, but it was accepted"
    err = exc.response.get("Error", {}).get("Code")
    msg = exc.response.get("Error", {}).get("Message") or ""
    assert err in allowed, (
        f"expected {sorted(allowed)} when sending from an unverified identity, got {err!r}: {msg!r}"
    )
    if err == "MessageRejected":
        expected_msg = (
            "Email address is not verified. The following identities failed the check in region "
            f"{ctx.region.upper()}: {email}"
        )
    else:
        expected_msg = "Sending is paused for this account."
    assert msg == expected_msg, (
        f"AWS names the failing identity in the MessageRejected message; a generic refusal hides "
        f"which identity was at fault. Expected {expected_msg!r}, got {msg!r}"
    )

    sent_after = ses.get_send_quota()["SentLast24Hours"]
    assert sent_after - sent_before < 1.0, (
        f"a refused send must not be counted: SentLast24Hours moved by {sent_after - sent_before} "
        f"({sent_before} -> {sent_after})"
    )
    status_after = _verification_status(ses, email)
    assert status_after == "Pending", (
        f"a refused send must not have verified the sender as a side effect, got {status_after!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
