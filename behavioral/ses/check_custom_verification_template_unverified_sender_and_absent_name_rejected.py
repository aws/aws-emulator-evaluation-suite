"""custom-verification-template-unverified-sender-and-absent-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-verification-template-unverified-sender-and-absent-name-rejected"
GROUP = "negative-classes"
SERVICES = ["ses"]

_ABSENT = "Provided custom verification email template name does not exist."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a custom verification template from an unverified sender is refused and stores
    nothing: Get and Update of that name then report it absent, while Delete of it succeeds."""
    ses = ctx.client("ses")
    name = ctx.unique_name("sim2real-behav-cvt-")
    sender = f"{ctx.unique_name('sim2real-behav-cvfrom-')}@example.com"

    code, message = _error(
        lambda: ses.create_custom_verification_email_template(
            TemplateName=name,
            FromEmailAddress=sender,
            TemplateSubject="Please verify",
            TemplateContent="<html><body>Please verify your address.</body></html>",
            SuccessRedirectionURL="https://example.com/success",
            FailureRedirectionURL="https://example.com/failure",
        )
    )
    # A template that slipped through is removed with the check.
    ctx.on_cleanup(lambda: ses.delete_custom_verification_email_template(TemplateName=name))
    assert code == "FromEmailAddressNotVerified", (
        f"expected FromEmailAddressNotVerified, got {code!r}: {message!r}"
    )
    expected = f"The from email address {sender} is not verified."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code, message = _error(lambda: ses.get_custom_verification_email_template(TemplateName=name))
    assert (code, message) == ("CustomVerificationEmailTemplateDoesNotExist", _ABSENT), (
        f"getting the refused template gave {code!r}: {message!r}"
    )

    code, message = _error(
        lambda: ses.update_custom_verification_email_template(
            TemplateName=name, TemplateSubject="nope"
        )
    )
    assert (code, message) == ("CustomVerificationEmailTemplateDoesNotExist", _ABSENT), (
        f"updating the refused template gave {code!r}: {message!r}"
    )

    listed = _listed_names(ses)
    assert name not in listed, f"the refused template {name!r} appears in the listing"

    # Delete is idempotent: an absent name is not an error.
    ses.delete_custom_verification_email_template(TemplateName=name)
    code, message = _error(lambda: ses.get_custom_verification_email_template(TemplateName=name))
    assert code == "CustomVerificationEmailTemplateDoesNotExist", (
        f"the name reads back after delete: {code!r}: {message!r}"
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _listed_names(ses) -> set[str]:
    names: set[str] = set()
    kwargs: dict = {"MaxResults": 50}
    while True:
        page = ses.list_custom_verification_email_templates(**kwargs)
        names |= {t["TemplateName"] for t in page.get("CustomVerificationEmailTemplates", [])}
        if not page.get("NextToken"):
            return names
        kwargs["NextToken"] = page["NextToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
