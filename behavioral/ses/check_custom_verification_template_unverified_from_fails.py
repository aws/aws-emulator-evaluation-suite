"""custom-verification-template-unverified-from-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-verification-template-unverified-from-fails"
GROUP = 'overly-permissive'
SERVICES = ['ses']

_ABSENT_MESSAGE = "Provided custom verification email template name does not exist."


def _err(fn):
    """Call fn() and return (Error.Code, Error.Message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


def _unique_email(ctx, prefix="probe-"):
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}@example.com"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "requires:dns-baseline")
def run(ctx) -> None:
    """CreateCustomVerificationEmailTemplate rejects an unverified FromEmailAddress
    (FromEmailAddressNotVerified) and leaves nothing behind; the identical call must
    succeed for a verified sender, or the rejection is indistinguishable from a blanket denial."""
    ses = ctx.client("ses")
    from_email = _unique_email(ctx, "cvfrom-")
    ses.verify_email_identity(EmailAddress=from_email)
    ctx.on_cleanup(lambda _n=from_email: ses.delete_identity(Identity=_n))

    name = ctx.unique_name("sim2real-behav-cvtmpl-")
    code, message = _err(
        lambda: ses.create_custom_verification_email_template(
            TemplateName=name,
            FromEmailAddress=from_email,
            TemplateSubject="Please verify",
            TemplateContent="<html><body>Please verify your address.</body></html>",
            SuccessRedirectionURL="https://example.com/success",
            FailureRedirectionURL="https://example.com/failure",
        )
    )
    assert code == "FromEmailAddressNotVerified", (
        f"expected FromEmailAddressNotVerified for an unverified sender, got {code!r}: {message!r}"
    )
    expected_message = f"The from email address {from_email} is not verified."
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # Nothing may have been created by the rejected call.
    get_code, get_message = _err(
        lambda: ses.get_custom_verification_email_template(TemplateName=name)
    )
    assert (get_code, get_message) == ("CustomVerificationEmailTemplateDoesNotExist", _ABSENT_MESSAGE), (
        f"expected the rejected custom verification template to not exist, got {get_code!r}: {get_message!r}"
    )

    # Positive control: the identical operation, differing only in the sender's
    # verification state, succeeds — so the rejection above is specific to the
    # unverified from-address rather than a blanket denial of the call.
    good_sender = _verified_sender_email(ctx)
    good_name = ctx.unique_name("sim2real-behav-cvtmpl-pos-")
    ses.create_custom_verification_email_template(
        TemplateName=good_name,
        FromEmailAddress=good_sender,
        TemplateSubject="Please verify",
        TemplateContent="<html><body>Please verify your address.</body></html>",
        SuccessRedirectionURL="https://example.com/success",
        FailureRedirectionURL="https://example.com/failure",
    )
    ctx.on_cleanup(lambda: ses.delete_custom_verification_email_template(TemplateName=good_name))
    got = ses.get_custom_verification_email_template(TemplateName=good_name)
    assert got["FromEmailAddress"] == good_sender, (
        f"expected the verified-sender template to record {good_sender!r}, got {got.get('FromEmailAddress')!r}"
    )


def _verified_sender_email(ctx):
    """A sender email under an identity this account has verified, such as its DNS baseline
    domain; verification needs an inbox click or a DNS record, which a check cannot make."""
    discovered = _find_verified_identity(ctx)
    if discovered:
        return discovered
    raise AssertionError("the account has no SES identity verified for sending")


def _find_verified_identity(ctx) -> str | None:
    ses = ctx.client("ses")
    for identity_type, synthesize in (
        ("EmailAddress", lambda identity: identity),
        ("Domain", lambda identity: f"sim2real-probe@{identity}"),
    ):
        identities = ses.list_identities(IdentityType=identity_type, MaxItems=100).get("Identities", [])
        if not identities:
            continue
        attrs = ses.get_identity_verification_attributes(Identities=identities)["VerificationAttributes"]
        for identity, info in attrs.items():
            if info.get("VerificationStatus") == "Success":
                return synthesize(identity)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
