"""put-email-identity-feedback-attributes-toggles-email-forwarding."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-email-identity-feedback-attributes-toggles-email-forwarding"
GROUP = "identity-v2"
SERVICES = ["sesv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutEmailIdentityFeedbackAttributes(EmailForwardingEnabled=...) toggles bounce/complaint
    email forwarding, and each new value is visible through GetEmailIdentity's
    FeedbackForwardingStatus.
    """
    ses = ctx.client("sesv2")
    domain = ctx.unique_name("sim2real-behav-fwdtoggle-") + ".example.com"
    ses.create_email_identity(
        EmailIdentity=domain, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: ses.delete_email_identity(EmailIdentity=domain))

    # A freshly created identity forwards bounce/complaint notifications by email by default.
    initial = ses.get_email_identity(EmailIdentity=domain)
    assert initial["FeedbackForwardingStatus"] is True, (
        f"expected a freshly created identity to have FeedbackForwardingStatus=True, got "
        f"{initial.get('FeedbackForwardingStatus')!r}"
    )

    ses.put_email_identity_feedback_attributes(EmailIdentity=domain, EmailForwardingEnabled=False)
    disabled = ses.get_email_identity(EmailIdentity=domain)
    assert disabled["FeedbackForwardingStatus"] is False, (
        f"PutEmailIdentityFeedbackAttributes(EmailForwardingEnabled=False) did not stick: "
        f"GetEmailIdentity reports FeedbackForwardingStatus={disabled.get('FeedbackForwardingStatus')!r}"
    )

    ses.put_email_identity_feedback_attributes(EmailIdentity=domain, EmailForwardingEnabled=True)
    reenabled = ses.get_email_identity(EmailIdentity=domain)
    assert reenabled["FeedbackForwardingStatus"] is True, (
        f"PutEmailIdentityFeedbackAttributes(EmailForwardingEnabled=True) did not stick: "
        f"GetEmailIdentity reports FeedbackForwardingStatus={reenabled.get('FeedbackForwardingStatus')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
