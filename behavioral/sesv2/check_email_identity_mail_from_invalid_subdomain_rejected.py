"""email-identity-mail-from-invalid-subdomain-rejected."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "email-identity-mail-from-invalid-subdomain-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sesv2']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """MailFromDomain that is not a subdomain of the identity MUST be rejected.

    Positive control (a real subdomain) must succeed and be independently readable back before the
    negative is meaningful; the rejected call must then leave that reading unchanged.
    """
    ses = ctx.client('sesv2')
    domain = ctx.unique_name('sim2real-behav-identity-domain-') + '.example.com'
    ses.create_email_identity(EmailIdentity=domain, Tags=[{'Key': 'sim2real-check', 'Value': CHECK}])
    ctx.on_cleanup(lambda _k=domain: ses.delete_email_identity(EmailIdentity=_k))

    valid_mail_from = f'mail.{domain}'
    ses.put_email_identity_mail_from_attributes(EmailIdentity=domain, MailFromDomain=valid_mail_from, BehaviorOnMxFailure='USE_DEFAULT_VALUE')
    before = ses.get_email_identity(EmailIdentity=domain)['MailFromAttributes']
    assert before['MailFromDomain'] == valid_mail_from, f'positive control failed: expected {valid_mail_from!r}, got {before.get("MailFromDomain")!r}'

    unrelated = 'totally-unrelated-domain.org'
    err = _error(lambda: ses.put_email_identity_mail_from_attributes(EmailIdentity=domain, MailFromDomain=unrelated, BehaviorOnMxFailure='USE_DEFAULT_VALUE'))
    assert err.get('Code') == 'BadRequestException', f'expected BadRequestException, got {err!r}'
    expected = f'Provided MAIL-FROM domain <{unrelated}> is not subdomain of the domain of the identity <{domain}>.'
    assert err.get('Message') == expected, f"expected message {expected!r}, got {err.get('Message')!r}"

    after = ses.get_email_identity(EmailIdentity=domain)['MailFromAttributes']
    assert after['MailFromDomain'] == valid_mail_from, f'rejected call must leave the prior MAIL FROM domain in place: expected {valid_mail_from!r}, got {after.get("MailFromDomain")!r}'


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
