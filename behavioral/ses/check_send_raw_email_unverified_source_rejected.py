"""send-raw-email-unverified-source-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-raw-email-unverified-source-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ses']


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


def _unique_email(ctx, prefix="probe-"):
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}@example.com"


def _raw_message(sender, subject):
    return (
        f"From: {sender}\r\n"
        f"To: {sender}\r\n"
        f"Subject: {subject}\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "raw body\r\n"
    ).encode("utf-8")


def _verification_status(ses, identity):
    entry = ses.get_identity_verification_attributes(
        Identities=[identity]
    ).get("VerificationAttributes", {}).get(identity)
    return entry.get("VerificationStatus") if entry else None


def _send_raw(ctx, ses, sender, subject):
    """The Error dict of a refused SendRawEmail: MessageRejected, or the paused refusal while
    sending is paused."""
    exc, allowed = _send_refusal(
        ctx,
        "ses",
        lambda: ses.send_raw_email(RawMessage={"Data": _raw_message(sender, subject)}),
        "MessageRejected",
    )
    assert exc is not None, "expected the SendRawEmail to be refused, but it SUCCEEDED"
    error = exc.response.get("Error", {})
    assert error.get("Code") in allowed, (
        f"expected {sorted(allowed)} for an unverified SendRawEmail source, got "
        f"{error.get('Code')!r}: {error.get('Message')!r}"
    )
    return error


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendRawEmail refuses a Pending source and a never-verified source with MessageRejected, each
    message naming its own identity; neither refusal verifies the sender or counts a send."""
    ses = ctx.client("ses")

    pending_sender = _unique_email(ctx, "raw-pending-")
    ses.verify_email_identity(EmailAddress=pending_sender)
    ctx.on_cleanup(lambda _n=pending_sender: ses.delete_identity(Identity=_n))

    status = _verification_status(ses, pending_sender)
    assert status == "Pending", (
        f"precondition: a freshly requested email identity should be Pending, got {status!r}"
    )

    quota_before = ses.get_send_quota()["SentLast24Hours"]

    err_pending = _send_raw(ctx, ses, pending_sender, "sim2real raw probe pending")
    pending_msg = (
        "Email address is not verified. The following identities failed the check in region "
        f"{ctx.region.upper()}: {pending_sender}"
    )
    if err_pending.get("Code") == "MessageRejected":
        assert err_pending.get("Message") == pending_msg, (
            f"expected the refusal to name the Pending identity {pending_sender!r}, got "
            f"{err_pending.get('Message')!r}"
        )

    # A second source VerifyEmailIdentity was never called for; its message must name ITS identity.
    never_created = _unique_email(ctx, "raw-ghost-")
    err_ghost = _send_raw(ctx, ses, never_created, "sim2real raw probe ghost")
    ghost_msg = (
        "Email address is not verified. The following identities failed the check in region "
        f"{ctx.region.upper()}: {never_created}"
    )
    if err_ghost.get("Code") == "MessageRejected":
        assert err_ghost.get("Message") == ghost_msg, (
            f"expected the refusal to name the never-verified identity {never_created!r}, got "
            f"{err_ghost.get('Message')!r}"
        )
    if err_ghost.get("Code") == err_pending.get("Code") == "MessageRejected":
        assert err_ghost.get("Message") != err_pending.get("Message"), (
            "two different unverified sources must not collapse into one byte-identical "
            f"MessageRejected message; both said {err_pending.get('Message')!r}"
        )

    status_after = _verification_status(ses, pending_sender)
    assert status_after == "Pending", (
        f"a refused SendRawEmail must not verify the sender, got {status_after!r}"
    )
    ghost_status = _verification_status(ses, never_created)
    assert ghost_status is None, (
        f"a never-verified sender must still be untracked after the refused send, got "
        f"{ghost_status!r}"
    )
    quota_after = ses.get_send_quota()["SentLast24Hours"]
    delta = quota_after - quota_before
    assert delta < 1.0, (
        f"two refused SendRawEmail calls must not be counted against the 24h send quota: "
        f"{quota_before} -> {quota_after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
