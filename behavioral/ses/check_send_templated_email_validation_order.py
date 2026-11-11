"""send-templated-email-validation-order."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-templated-email-validation-order"
GROUP = 'sending'
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


def _verification_status(ses, identity):
    entry = ses.get_identity_verification_attributes(
        Identities=[identity]
    ).get("VerificationAttributes", {}).get(identity)
    return entry.get("VerificationStatus") if entry else None


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendTemplatedEmail checks sender verification BEFORE template existence: MessageRejected
    naming the sender, identical whether the template is missing or exists, with nothing sent.
    """
    ses = ctx.client("ses")
    sender = _unique_email(ctx, "sender-")
    ses.verify_email_identity(EmailAddress=sender)
    ctx.on_cleanup(lambda _n=sender: ses.delete_identity(Identity=_n))

    status = _verification_status(ses, sender)
    assert status == "Pending", (
        f"precondition: a freshly requested email identity should be Pending, got {status!r}"
    )

    existing_template = ctx.unique_name("sim2real-behav-tmpl-exists-")
    ses.create_template(Template={
        "TemplateName": existing_template,
        "SubjectPart": "probe",
        "TextPart": "probe body",
    })
    ctx.on_cleanup(lambda _n=existing_template: ses.delete_template(TemplateName=_n))

    sent_before = ses.get_send_quota()["SentLast24Hours"]
    # The SES mailbox simulator is exempt from the sandbox recipient gate, so the refusal names
    # only the sender. An unverified recipient would be listed too, in no stable order.
    to_addr = "success@simulator.amazonses.com"

    missing_template = ctx.unique_name("sim2real-behav-tmpl-missing-")
    exc_missing, allowed = _send_refusal(ctx, "ses", lambda: ses.send_templated_email(
        Source=sender,
        Destination={"ToAddresses": [to_addr]},
        Template=missing_template,
        TemplateData="{}",
    ), "MessageRejected")
    assert exc_missing is not None, "expected the send with a MISSING template to be refused"
    code_missing = exc_missing.response.get("Error", {}).get("Code")
    msg_missing = exc_missing.response.get("Error", {}).get("Message") or ""
    assert code_missing in allowed, (
        f"expected {sorted(allowed)} (identity gate before template lookup) for a MISSING "
        f"template, got {code_missing!r}: {msg_missing!r}"
    )
    expected_msg = (
        "Email address is not verified. The following identities failed the check in region "
        f"{ctx.region.upper()}: {sender}"
    )
    if code_missing == "MessageRejected":
        assert msg_missing == expected_msg, (
            f"AWS names the failing identity in the MessageRejected message; a generic refusal "
            f"hides which identity was at fault. Expected {expected_msg!r}, got {msg_missing!r}"
        )

    # No successful send as a control: verifying the sender needs a real mailbox click-through.
    exc_existing, allowed = _send_refusal(ctx, "ses", lambda: ses.send_templated_email(
        Source=sender,
        Destination={"ToAddresses": [to_addr]},
        Template=existing_template,
        TemplateData="{}",
    ), "MessageRejected")
    assert exc_existing is not None, "expected the send with an existing template to be refused"
    code_existing = exc_existing.response.get("Error", {}).get("Code")
    msg_existing = exc_existing.response.get("Error", {}).get("Message") or ""
    assert code_existing in allowed, (
        f"the SAME unverified sender must be rejected identically when the template DOES "
        f"exist -- anything other than {sorted(allowed)} here means the identity gate is not "
        f"truly ahead of template resolution, got {code_existing!r}: {msg_existing!r}"
    )
    if code_existing == "MessageRejected":
        assert msg_existing == expected_msg, (
            f"expected {expected_msg!r}, got {msg_existing!r}"
        )

    sent_after = ses.get_send_quota()["SentLast24Hours"]
    assert sent_after - sent_before < 1.0, (
        f"two refused sends must not be counted: SentLast24Hours moved by "
        f"{sent_after - sent_before} ({sent_before} -> {sent_after})"
    )
    status_after = _verification_status(ses, sender)
    assert status_after == "Pending", (
        f"a refused send must not have verified the sender as a side effect, got {status_after!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
