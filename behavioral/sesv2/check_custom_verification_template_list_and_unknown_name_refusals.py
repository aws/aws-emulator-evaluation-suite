"""custom-verification-template-list-and-unknown-name-refusals."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-verification-template-list-and-unknown-name-refusals"
GROUP = "custom-verification-v2"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SESv2 ListCustomVerificationEmailTemplates excludes a never-created template; Get and
    Delete on that name raise NotFoundException naming the template, while Update with an
    unverified FromEmailAddress names that address instead."""
    ses = ctx.client("sesv2")

    ghost_a = ctx.unique_name("sim2real-cvet-ghost-a-")
    ghost_b = ctx.unique_name("sim2real-cvet-ghost-b-")
    from_a = ctx.unique_name("sim2real-cvet-from-a-") + "@example.com"
    from_b = ctx.unique_name("sim2real-cvet-from-b-") + "@example.com"

    _assert_absent(ses, ghost_a, ghost_b)

    get_a = _error(lambda: ses.get_custom_verification_email_template(TemplateName=ghost_a))
    assert get_a == ("NotFoundException", f"Custom verification email template <{ghost_a}> does not exist"), (
        f"expected Get on {ghost_a!r} to raise NotFoundException naming that template, got {get_a!r}"
    )
    get_b = _error(lambda: ses.get_custom_verification_email_template(TemplateName=ghost_b))
    assert get_b == ("NotFoundException", f"Custom verification email template <{ghost_b}> does not exist"), (
        f"expected Get on {ghost_b!r} to raise NotFoundException naming that template, got {get_b!r}"
    )

    update_a = _error(lambda: ses.update_custom_verification_email_template(
        TemplateName=ghost_a,
        FromEmailAddress=from_a,
        TemplateSubject="Verify your email",
        TemplateContent="<p>Please verify your email address.</p>",
        SuccessRedirectionURL="https://example.com/success",
        FailureRedirectionURL="https://example.com/failure",
    ))
    assert update_a == ("NotFoundException", f"The from email address <{from_a}> is not verified"), (
        f"expected Update on {ghost_a!r} with unverified sender {from_a!r} to raise NotFoundException "
        f"naming the sender, got {update_a!r}"
    )
    update_b = _error(lambda: ses.update_custom_verification_email_template(
        TemplateName=ghost_b,
        FromEmailAddress=from_b,
        TemplateSubject="Verify your email",
        TemplateContent="<p>Please verify your email address.</p>",
        SuccessRedirectionURL="https://example.com/success",
        FailureRedirectionURL="https://example.com/failure",
    ))
    assert update_b == ("NotFoundException", f"The from email address <{from_b}> is not verified"), (
        f"expected Update on {ghost_b!r} with unverified sender {from_b!r} to raise NotFoundException "
        f"naming the sender, got {update_b!r}"
    )

    delete_a = _error(lambda: ses.delete_custom_verification_email_template(TemplateName=ghost_a))
    assert delete_a == ("NotFoundException", f"Custom verification email template <{ghost_a}> does not exist"), (
        f"expected Delete on {ghost_a!r} to raise NotFoundException naming that template, got {delete_a!r}"
    )
    delete_b = _error(lambda: ses.delete_custom_verification_email_template(TemplateName=ghost_b))
    assert delete_b == ("NotFoundException", f"Custom verification email template <{ghost_b}> does not exist"), (
        f"expected Delete on {ghost_b!r} to raise NotFoundException naming that template, got {delete_b!r}"
    )

    # Effect absent: none of the refused Get/Update/Delete calls above conjured either name into
    # existence.
    _assert_absent(ses, ghost_a, ghost_b)


def _assert_absent(ses, *names: str) -> None:
    seen = set()
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = ses.list_custom_verification_email_templates(**kwargs)
        assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
            f"expected ListCustomVerificationEmailTemplates to return 200 with no sending "
            f"identity configured, got {resp['ResponseMetadata']['HTTPStatusCode']}"
        )
        for t in resp.get("CustomVerificationEmailTemplates", []):
            seen.add(t["TemplateName"])
        token = resp.get("NextToken")
        if not token:
            break
    for name in names:
        assert name not in seen, f"expected {name!r}, never created, to be absent from the listing"


def _error(fn):
    """The (Error.Code, Error.Message) of the ClientError ``fn`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
