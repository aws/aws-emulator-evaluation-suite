"""send-email-pending-identity-still-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-email-pending-identity-still-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ses']

def _err(fn):
    """Call fn(); return the (Code, Message) of the ClientError it raises; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the send to be refused, but it succeeded and returned {result!r}")


def _unique_email(ctx, prefix="probe-"):
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}@example.com"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendEmail from a Pending identity is rejected with MessageRejected naming that sender and the
    region, and the refusal does not verify it."""
    ses = ctx.client("ses")

    sender = _unique_email(ctx, "pending-")
    ses.verify_email_identity(EmailAddress=sender)
    ctx.on_cleanup(lambda _n=sender: ses.delete_identity(Identity=_n))

    status = ses.get_identity_verification_attributes(Identities=[sender])[
        "VerificationAttributes"
    ][sender]["VerificationStatus"]
    assert status == "Pending", f"expected Pending sender, got {status!r}"

    err, msg = _err(
        lambda: ses.send_email(
            Source=sender,
            Destination={"ToAddresses": [sender]},
            Message={"Subject": {"Data": "hi"}, "Body": {"Text": {"Data": "body"}}},
        )
    )
    assert err == "MessageRejected", (
        f"expected MessageRejected sending from a Pending identity, got {err!r}: {msg!r}"
    )
    expected_msg = (
        "Email address is not verified. The following identities failed the check in region "
        f"{ctx.region.upper()}: {sender}"
    )
    assert msg == expected_msg, (
        f"the refusal must name the Pending sender: expected {expected_msg!r}, got {msg!r}"
    )

    # No Success-verified positive control is possible (verification needs a mailbox click-through
    # or published DNS), so specificity rests on the exact message naming this sender.
    still = ses.get_identity_verification_attributes(Identities=[sender])[
        "VerificationAttributes"
    ][sender]["VerificationStatus"]
    assert still == "Pending", (
        f"a rejected send must not verify the sender, got {still!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
