"""identity-mail-from-domain-pending-transition."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "identity-mail-from-domain-pending-transition"
GROUP = 'identity'
SERVICES = ['ses']

def _unique_domain(ctx, prefix="probe-"):
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}.example.com"


def _mail_from_attributes(ses, identity):
    return ses.get_identity_mail_from_domain_attributes(
        Identities=[identity]
    ).get("MailFromDomainAttributes", {}).get(identity)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetIdentityMailFromDomain puts MailFromDomainStatus in Pending for the new custom MAIL FROM domain."""
    ses = ctx.client("ses")
    domain = _unique_domain(ctx)
    ses.verify_domain_identity(Domain=domain)
    ctx.on_cleanup(lambda _n=domain: ses.delete_identity(Identity=_n))

    mail_from_domain = f"bounce.{domain}"
    ses.set_identity_mail_from_domain(
        Identity=domain, MailFromDomain=mail_from_domain, BehaviorOnMXFailure="UseDefaultValue"
    )
    attrs = _mail_from_attributes(ses, domain)
    assert attrs is not None, "no MailFromDomainAttributes entry after SetIdentityMailFromDomain"
    assert attrs.get("MailFromDomain") == mail_from_domain, (
        f"MailFromDomain not reflected: {attrs.get('MailFromDomain')!r} != {mail_from_domain!r}"
    )
    assert attrs.get("MailFromDomainStatus") == "Pending", (
        f"expected new MAIL FROM domain to start Pending, got {attrs.get('MailFromDomainStatus')!r}"
    )
    assert attrs.get("BehaviorOnMXFailure") == "UseDefaultValue", (
        f"expected BehaviorOnMXFailure UseDefaultValue, got {attrs.get('BehaviorOnMXFailure')!r}"
    )

    # BehaviorOnMXFailure is mutable in place and must not reset the domain.
    ses.set_identity_mail_from_domain(
        Identity=domain, MailFromDomain=mail_from_domain, BehaviorOnMXFailure="RejectMessage"
    )
    attrs_mx = _mail_from_attributes(ses, domain)
    assert attrs_mx.get("BehaviorOnMXFailure") == "RejectMessage", (
        f"BehaviorOnMXFailure not updated: {attrs_mx}"
    )
    assert attrs_mx.get("MailFromDomain") == mail_from_domain, (
        f"MailFromDomain changed by BehaviorOnMXFailure update: {attrs_mx.get('MailFromDomain')!r} != {mail_from_domain!r}"
    )

    # Omitting MailFromDomain removes the custom MAIL FROM configuration.
    ses.set_identity_mail_from_domain(Identity=domain)
    attrs_after = _mail_from_attributes(ses, domain)
    assert attrs_after is None or not attrs_after.get("MailFromDomain"), (
        f"MailFromDomain still set after removal: {attrs_after}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
