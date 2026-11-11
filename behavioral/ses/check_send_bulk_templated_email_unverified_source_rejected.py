"""send-bulk-templated-email-unverified-source-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-bulk-templated-email-unverified-source-rejected"
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


def _verification_status(ses, identity):
    entry = ses.get_identity_verification_attributes(
        Identities=[identity]
    ).get("VerificationAttributes", {}).get(identity)
    return entry.get("VerificationStatus") if entry else None


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendBulkTemplatedEmail with an unverified Source must fail atomically (MessageRejected), not
    per-destination, must not consume the 24-hour send allowance, and must not verify the source as a
    side effect of the rejected attempt."""
    ses = ctx.client("ses")
    email = _unique_email(ctx)
    ses.verify_email_identity(EmailAddress=email)
    ctx.on_cleanup(lambda _n=email: ses.delete_identity(Identity=_n))

    status = _verification_status(ses, email)
    assert status == "Pending", (
        f"precondition: a freshly requested email identity should be Pending, got {status!r}"
    )

    template_name = ctx.unique_name("sim2real-behav-tmpl-bulk-")
    ses.create_template(
        Template={
            "TemplateName": template_name,
            "SubjectPart": "Hello {{name}}",
            "HtmlPart": "<p>Hi {{name}}</p>",
            "TextPart": "Hi {{name}}",
        }
    )
    ctx.on_cleanup(lambda _n=template_name: ses.delete_template(TemplateName=_n))

    sent_before = ses.get_send_quota()["SentLast24Hours"]

    destinations = [
        {"Destination": {"ToAddresses": [email]}, "ReplacementTemplateData": '{"name": "Alice"}'},
        {"Destination": {"ToAddresses": [email]}, "ReplacementTemplateData": '{"name": "Bob"}'},
    ]
    exc, allowed = _send_refusal(
        ctx,
        "ses",
        lambda: ses.send_bulk_templated_email(
            Source=email,
            Template=template_name,
            DefaultTemplateData='{"name": "Default"}',
            Destinations=destinations,
        ),
        "MessageRejected",
    )
    assert exc is not None, "expected the bulk send to be refused, but it succeeded"
    err = exc.response.get("Error", {}).get("Code")
    msg = exc.response.get("Error", {}).get("Message")
    assert err in allowed, (
        f"expected {sorted(allowed)} for an unverified bulk-send Source, got {err!r}: {msg!r}"
    )
    if err == "MessageRejected":
        expected_msg = (
            "Email address is not verified. The following identities failed the check in region "
            f"{ctx.region.upper()}: {email}"
        )
        assert msg == expected_msg, (
            f"the refusal must name the unverified Source: expected {expected_msg!r}, got {msg!r}"
        )

    # Effect absent, via independent reads: a refused bulk send must not consume the account's send
    # allowance, and must not implicitly verify the rejected source as a side effect of the attempt.
    sent_after = ses.get_send_quota()["SentLast24Hours"]
    delta = sent_after - sent_before
    assert delta < 1.0, (
        f"a refused bulk send must not be counted against the send allowance: SentLast24Hours moved "
        f"by {delta} ({sent_before} -> {sent_after})"
    )
    status_after = _verification_status(ses, email)
    assert status_after == "Pending", (
        f"a refused bulk send must not verify its source as a side effect, got {status_after!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
