"""custom-verification-template-not-found-semantics."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-verification-template-not-found-semantics"
GROUP = 'templates'
SERVICES = ['ses']

_ABSENT_MESSAGE = "Provided custom verification email template name does not exist."
_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "requires:dns-baseline")
def run(ctx) -> None:
    """Get/Update on an absent custom verification template raise CustomVerificationEmailTemplateDoesNotExist,
    with a positive control proving the identical calls succeed against a template that exists. List
    stays consistent in both cases."""
    ses = ctx.client("ses")
    absent_name = ctx.unique_name("sim2real-behav-cvt-absent-")

    sender = _verified_sender_email(ctx)
    real_name = ctx.unique_name("sim2real-behav-cvt-real-")
    ses.create_custom_verification_email_template(
        TemplateName=real_name,
        FromEmailAddress=sender,
        TemplateSubject="Please verify",
        TemplateContent="<html><body>Please verify your address.</body></html>",
        SuccessRedirectionURL="https://example.com/success",
        FailureRedirectionURL="https://example.com/failure",
    )
    ctx.on_cleanup(lambda: ses.delete_custom_verification_email_template(TemplateName=real_name))

    got = ses.get_custom_verification_email_template(TemplateName=real_name)
    assert got.get("TemplateSubject") == "Please verify", (
        f"expected the just-created template's subject to round-trip, got {got.get('TemplateSubject')!r}"
    )
    assert got.get("FromEmailAddress") == sender, (
        f"expected the just-created template's sender to round-trip, got {got.get('FromEmailAddress')!r}"
    )

    listed_control = ses.list_custom_verification_email_templates()
    control_names = {t["TemplateName"] for t in listed_control.get("CustomVerificationEmailTemplates", [])}
    assert real_name in control_names, "just-created custom verification template missing from listing"

    code, message = _error(lambda: ses.get_custom_verification_email_template(TemplateName=absent_name))
    assert (code, message) == ("CustomVerificationEmailTemplateDoesNotExist", _ABSENT_MESSAGE), (
        f"expected DoesNotExist getting an absent custom verification template, got {code!r}: {message!r}"
    )

    code, message = _error(
        lambda: ses.update_custom_verification_email_template(
            TemplateName=absent_name, TemplateSubject="nope"
        )
    )
    assert (code, message) == ("CustomVerificationEmailTemplateDoesNotExist", _ABSENT_MESSAGE), (
        f"expected DoesNotExist updating an absent custom verification template, got {code!r}: {message!r}"
    )

    listed = ses.list_custom_verification_email_templates()
    names = {t["TemplateName"] for t in listed.get("CustomVerificationEmailTemplates", [])}
    assert absent_name not in names, "absent custom verification template leaked into the listing"
    assert real_name in names, "positive-control template disappeared from the listing during the negative checks"


def _verified_sender_email(ctx):
    domain = _sending_domain(ctx, ctx.client("route53"), ctx.client("sesv2"))
    return f"{ctx.unique_name('sim2real-probe-')}@{domain}"


def _sending_domain(ctx, route53, sesv2):
    """The account's DNS baseline domain, the apex of its public hosted zone tagged
    _BASELINE_TAG, which SES has verified."""
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
                    f"the DNS baseline domain {domain!r} is not verified for sending in "
                    f"{ctx.region} (DKIM {identity['DkimAttributes']['Status']!r})"
                )
                return domain
    raise AssertionError(
        "no public hosted zone carries the DNS baseline tag, so the account has "
        "no verified domain to send from"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
