"""custom-verification-template-update-then-delete-then-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "custom-verification-template-update-then-delete-then-not-found"
GROUP = "state-machine"
SERVICES = ["ses"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "requires:dns-baseline")
def run(ctx) -> None:
    """UpdateCustomVerificationEmailTemplate changes the subject, content and redirect URLs in place;
    after deletion GetCustomVerificationEmailTemplate answers CustomVerificationEmailTemplateDoesNotExist
    with its exact message and the listing omits the template."""
    ses = ctx.client("ses")
    sender = _verified_sender_email(ctx)
    name = ctx.unique_name("sim2real-ses-cvt-")

    ses.create_custom_verification_email_template(
        TemplateName=name,
        FromEmailAddress=sender,
        TemplateSubject="Please verify (v1)",
        TemplateContent="<html><body><p>Verify your address (v1).</p></body></html>",
        SuccessRedirectionURL="https://example.com/ok-v1",
        FailureRedirectionURL="https://example.com/fail-v1",
    )
    cleaned = {"done": False}

    def _cleanup():
        if not cleaned["done"]:
            ses.delete_custom_verification_email_template(TemplateName=name)

    ctx.on_cleanup(_cleanup)

    ses.update_custom_verification_email_template(
        TemplateName=name,
        TemplateSubject="Please verify (v2)",
        TemplateContent="<html><body><p>Verify your address (v2).</p></body></html>",
        SuccessRedirectionURL="https://example.com/ok-v2",
        FailureRedirectionURL="https://example.com/fail-v2",
    )

    got = ses.get_custom_verification_email_template(TemplateName=name)
    assert got["TemplateSubject"] == "Please verify (v2)", (
        f"expected updated subject 'Please verify (v2)', got {got['TemplateSubject']!r}"
    )
    assert "v2" in got["TemplateContent"] and "v1" not in got["TemplateContent"], (
        f"expected updated content to contain 'v2' and not 'v1', got {got['TemplateContent']!r}"
    )
    assert got["SuccessRedirectionURL"] == "https://example.com/ok-v2", (
        f"expected updated SuccessRedirectionURL 'https://example.com/ok-v2', got {got['SuccessRedirectionURL']!r}"
    )
    assert got["FailureRedirectionURL"] == "https://example.com/fail-v2", (
        f"expected updated FailureRedirectionURL 'https://example.com/fail-v2', got {got['FailureRedirectionURL']!r}"
    )

    listed_names = {
        t["TemplateName"] for t in ses.list_custom_verification_email_templates()["CustomVerificationEmailTemplates"]
    }
    assert name in listed_names, f"expected {name!r} in the template listing, got {listed_names!r}"

    ses.delete_custom_verification_email_template(TemplateName=name)
    cleaned["done"] = True

    code, message = _error_code(lambda: ses.get_custom_verification_email_template(TemplateName=name))
    assert code == "CustomVerificationEmailTemplateDoesNotExist", (
        f"expected CustomVerificationEmailTemplateDoesNotExist getting a deleted template, got {code!r}"
    )
    assert message == "Provided custom verification email template name does not exist.", message

    listed_after = {
        t["TemplateName"] for t in ses.list_custom_verification_email_templates()["CustomVerificationEmailTemplates"]
    }
    assert name not in listed_after, f"expected {name!r} absent from the listing after delete, got {listed_after!r}"


# ===== helpers =====
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


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
