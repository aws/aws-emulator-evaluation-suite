"""custom-verification-template-unverified-sender-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "custom-verification-template-unverified-sender-rejected"
GROUP = "state-machine"
SERVICES = ["ses"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "requires:dns-baseline")
def run(ctx) -> None:
    """CreateCustomVerificationEmailTemplate with a never-verified FromEmailAddress is refused with
    FromEmailAddressNotVerified and leaves no template (CustomVerificationEmailTemplateDoesNotExist),
    both with exact messages, while a verified sender creates the template."""
    ses = ctx.client("ses")
    unverified_email = ctx.unique_name("sim2real-ses-unverified-") + "@example.com"
    bad_name = ctx.unique_name("sim2real-ses-cvt-neg-")

    code, message = _error_code(
        lambda: ses.create_custom_verification_email_template(
            TemplateName=bad_name,
            FromEmailAddress=unverified_email,
            TemplateSubject="Verify",
            TemplateContent="<html><body>Verify your address.</body></html>",
            SuccessRedirectionURL="https://example.com/ok",
            FailureRedirectionURL="https://example.com/fail",
        )
    )
    assert code == "FromEmailAddressNotVerified", code
    assert message == f"The from email address {unverified_email} is not verified.", message

    # effect absent: the template must not have been created
    not_found_code, not_found_message = _error_code(
        lambda: ses.get_custom_verification_email_template(TemplateName=bad_name)
    )
    assert not_found_code == "CustomVerificationEmailTemplateDoesNotExist", not_found_code
    assert not_found_message == "Provided custom verification email template name does not exist.", not_found_message

    # positive control: the exact same operation succeeds with a verified sender
    good_sender = _verified_sender_email(ctx)
    good_name = ctx.unique_name("sim2real-ses-cvt-pos-")
    ses.create_custom_verification_email_template(
        TemplateName=good_name,
        FromEmailAddress=good_sender,
        TemplateSubject="Verify",
        TemplateContent="<html><body>Verify your address.</body></html>",
        SuccessRedirectionURL="https://example.com/ok",
        FailureRedirectionURL="https://example.com/fail",
    )
    ctx.on_cleanup(lambda: ses.delete_custom_verification_email_template(TemplateName=good_name))
    got = ses.get_custom_verification_email_template(TemplateName=good_name)
    assert got["FromEmailAddress"] == good_sender


# ===== helpers =====
def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _verified_sender_email(ctx):
    """An address under the target's verified sending domain (_sending_domain)."""
    domain = _sending_domain(ctx, ctx.client("route53"), ctx.client("sesv2"))
    return f"{ctx.unique_name('sim2real-ses-sender-')}@{domain}"


_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}


def _sending_domain(ctx, route53, sesv2):
    """The target's DNS baseline domain (its tagged public hosted zone, verified in SES); an account without one fails the check."""
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for z in page["HostedZones"]:
            if z["Config"].get("PrivateZone"):
                continue
            zone_tags = route53.list_tags_for_resource(
                ResourceType="hostedzone", ResourceId=z["Id"].rsplit("/", 1)[-1]
            )["ResourceTagSet"]["Tags"]
            if _BASELINE_TAG in zone_tags:
                domain = z["Name"].rstrip(".")
                identity = sesv2.get_email_identity(EmailIdentity=domain)
                assert identity["VerifiedForSendingStatus"], (
                    f"the DNS baseline domain {domain!r} is not verified in {ctx.region}; "
                    "verify it in SES before running this check"
                )
                return domain
    raise AssertionError(
        "this account has no DNS baseline zone (a public hosted zone carrying the baseline "
        "tag, verified in SES) and so no sending domain; the check requires one"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
