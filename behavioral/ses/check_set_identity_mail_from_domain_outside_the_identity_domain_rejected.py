"""set-identity-mail-from-domain-outside-the-identity-domain-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-identity-mail-from-domain-outside-the-identity-domain-rejected"
GROUP = "identity"
SERVICES = ["ses"]


def _error(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _mail_from(ses, identity):
    return ses.get_identity_mail_from_domain_attributes(
        Identities=[identity]
    ).get("MailFromDomainAttributes", {}).get(identity)


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetIdentityMailFromDomain refuses a MAIL FROM domain outside the identity's domain;
    the refused call leaves the configured MAIL FROM unchanged; a subdomain of the identity is accepted.
    """
    ses = ctx.client("ses")
    domain = f"{ctx.unique_name('sim2real-behav-mf-')}.example.com"
    ses.verify_domain_identity(Domain=domain)
    ctx.on_cleanup(lambda: ses.delete_identity(Identity=domain))
    good = f"bounce.{domain}"
    ses.set_identity_mail_from_domain(
        Identity=domain, MailFromDomain=good, BehaviorOnMXFailure="UseDefaultValue"
    )
    assert (_mail_from(ses, domain) or {}).get("MailFromDomain") == good, "subdomain not accepted"

    outside = f"bounce.{ctx.unique_name('sim2real-behav-other-')}.example.com"
    code, message = _error(lambda: ses.set_identity_mail_from_domain(
        Identity=domain, MailFromDomain=outside, BehaviorOnMXFailure="UseDefaultValue"
    ))
    assert code == "InvalidParameterValue", (
        f"a MAIL FROM outside the identity: got {code}: {message!r}"
    )
    expected = (
        f"Provided MAIL-FROM domain <{outside}> is not subdomain of the domain of the identity "
        f"<{domain}>."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    kept = _mail_from(ses, domain) or {}
    assert kept.get("MailFromDomain") == good, f"the refused call changed the MAIL FROM: {kept!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
