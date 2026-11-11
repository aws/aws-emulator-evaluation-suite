"""email-identity-v1-v2-shared-store."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "email-identity-v1-v2-shared-store"
GROUP = 'identity-v2'
SERVICES = ['ses']

from botocore.exceptions import ClientError

# v1 spells verification status in TitleCase, v2 in SCREAMING_CASE. The mapping is a contract, not a
# formatting detail: a caller that creates via one API and polls via the other depends on it.
_V1_TO_V2_STATUS = {'Pending': 'PENDING', 'Success': 'SUCCESS', 'Failed': 'FAILED', 'NotStarted': 'NOT_STARTED'}


def _get_or_none(fn):
    """Return fn() or None if the resource is not yet visible. Any other error still propagates."""
    try:
        return fn()
    except ClientError as exc:
        if exc.response['Error']['Code'] == 'NotFoundException':
            return None
        raise


def _delete_identity_if_present(client, **kwargs) -> None:
    """Cleanup that tolerates the check having already deleted the identity, and nothing else."""
    try:
        client(**kwargs)
    except ClientError as exc:
        if exc.response['Error']['Code'] not in ('NotFoundException', 'NotFound'):
            raise


def _poll(fn, *, timeout_s=60.0, interval_s=2.0):
    """Poll fn() until it returns a truthy value; raise on deadline miss."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(interval_s)
    raise AssertionError(f'condition not reached within {timeout_s}s; last observation was {last!r}')


def _unique_domain(ctx, prefix='shared-') -> str:
    # RFC 2606 reserved domain only.
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}.example.com"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SES v1 and SESv2 share one identity store: an identity created through either is visible,
    correctly typed and consistently statused through the other, and a v2 delete removes it from both.
    """
    v2 = ctx.client('sesv2')
    v1 = ctx.client('ses')
    account = ctx.client('sts').get_caller_identity()['Account']

    # --- direction 1: created via v2, read via v1 ---
    dom_v2 = _unique_domain(ctx, 'v2made-')
    v2.create_email_identity(EmailIdentity=dom_v2, Tags=[{'Key': 'sim2real-check', 'Value': CHECK}])
    ctx.on_cleanup(lambda _d=dom_v2: _delete_identity_if_present(v2.delete_email_identity, EmailIdentity=_d))

    v2_view = v2.get_email_identity(EmailIdentity=dom_v2)
    assert v2_view['IdentityType'] == 'DOMAIN', f"expected DOMAIN, got {v2_view.get('IdentityType')!r}"
    v2_status = v2_view['VerificationStatus']
    assert v2_status == 'PENDING', (
        f"a freshly created domain identity must be PENDING in v2, got {v2_status!r}"
    )

    v1_attrs = _poll(lambda: v1.get_identity_verification_attributes(
        Identities=[dom_v2])['VerificationAttributes'].get(dom_v2))
    assert _V1_TO_V2_STATUS.get(v1_attrs['VerificationStatus']) == v2_status, (
        f"v1 status {v1_attrs['VerificationStatus']!r} does not map to the v2 status {v2_status!r} for the "
        f"same identity; the two APIs are reporting different state"
    )
    assert (v1_attrs.get('VerificationToken') or '').strip(), (
        f"v1 must expose the TXT VerificationToken for a v2-created domain identity, got {v1_attrs!r}"
    )
    v1_list = _poll(lambda: dom_v2 in (v1.list_identities(IdentityType='Domain', MaxItems=1000).get('Identities') or []))
    assert v1_list is True, f"v1 ListIdentities must include the v2-created domain {dom_v2!r}"

    # --- direction 2: created via v1, read via v2 ---
    dom_v1 = _unique_domain(ctx, 'v1made-')
    v1.verify_domain_identity(Domain=dom_v1)
    ctx.on_cleanup(lambda _d=dom_v1: v1.delete_identity(Identity=_d))
    v2.tag_resource(ResourceArn=f"arn:aws:ses:{ctx.region}:{account}:identity/{dom_v1}",
                     Tags=[{'Key': 'sim2real-check', 'Value': CHECK}])

    v2_of_v1 = _poll(lambda: _get_or_none(lambda: v2.get_email_identity(EmailIdentity=dom_v1)))
    assert v2_of_v1['IdentityType'] == 'DOMAIN', (
        f"v2 must derive DOMAIN for a v1 VerifyDomainIdentity identity, got {v2_of_v1.get('IdentityType')!r}"
    )
    assert v2_of_v1['VerificationStatus'] == 'PENDING', (
        f"v2 must report PENDING for the v1-created domain, got {v2_of_v1.get('VerificationStatus')!r}"
    )
    assert v2_of_v1['VerifiedForSendingStatus'] is False, (
        f"an unverified domain cannot be verified for sending, got {v2_of_v1.get('VerifiedForSendingStatus')!r}"
    )
    # VerifyDomainIdentity does not start Easy DKIM (SigningEnabled=False, NOT_STARTED, no Tokens);
    # DKIM is the separate VerifyDomainDkim call, whose tokens the shared store must propagate.
    dkim_v1made = v2_of_v1.get('DkimAttributes') or {}
    assert dkim_v1made.get('SigningEnabled') is False, (
        f"VerifyDomainIdentity alone does not start Easy DKIM, got SigningEnabled="
        f"{dkim_v1made.get('SigningEnabled')!r}"
    )
    assert dkim_v1made.get('Status') == 'NOT_STARTED', (
        f"Easy DKIM must be NOT_STARTED until VerifyDomainDkim is called, got "
        f"{dkim_v1made.get('Status')!r}"
    )
    assert not (dkim_v1made.get('Tokens') or []), (
        f"a domain with Easy DKIM NOT_STARTED has no CNAME tokens to publish, got "
        f"{dkim_v1made.get('Tokens')!r}"
    )
    minted = v1.verify_domain_dkim(Domain=dom_v1)['DkimTokens']
    assert len(set(minted)) == 3, f"VerifyDomainDkim mints exactly three distinct tokens, got {minted!r}"
    tokens_v1made = _poll(
        lambda: (v2.get_email_identity(EmailIdentity=dom_v1).get('DkimAttributes') or {}).get('Tokens'))
    assert set(tokens_v1made) == set(minted), (
        f"v2 must serve the tokens v1 VerifyDomainDkim minted from the one store: v1={minted!r} "
        f"v2={tokens_v1made!r}"
    )
    assert (v2.get_email_identity(EmailIdentity=dom_v1)['DkimAttributes'].get('SigningEnabled')
            is True), 'v2 must report Easy DKIM enabled after the v1 VerifyDomainDkim'

    email_v1 = f"sim2real-behav-shared@{_unique_domain(ctx, 'v1mail-')}"
    v1.verify_email_identity(EmailAddress=email_v1)
    ctx.on_cleanup(lambda _e=email_v1: v1.delete_identity(Identity=_e))
    v2.tag_resource(ResourceArn=f"arn:aws:ses:{ctx.region}:{account}:identity/{email_v1}",
                     Tags=[{'Key': 'sim2real-check', 'Value': CHECK}])
    v2_of_email = _poll(lambda: _get_or_none(lambda: v2.get_email_identity(EmailIdentity=email_v1)))
    assert v2_of_email['IdentityType'] == 'EMAIL_ADDRESS', (
        f"v2 must derive EMAIL_ADDRESS for a v1 VerifyEmailIdentity identity, got "
        f"{v2_of_email.get('IdentityType')!r}"
    )

    # --- delete through v2 removes it from v1 ---
    v2.delete_email_identity(EmailIdentity=dom_v2)
    gone_from_v1 = _poll(
        lambda: dom_v2 not in (v1.list_identities(IdentityType='Domain', MaxItems=1000).get('Identities') or []))
    assert gone_from_v1 is True, f"v1 ListIdentities must no longer include {dom_v2!r} after it was deleted through v2"
    v1_after = v1.get_identity_verification_attributes(
        Identities=[dom_v2])['VerificationAttributes']
    assert dom_v2 not in v1_after, (
        f"v1 still reports verification attributes for an identity deleted through v2: {v1_after!r}"
    )

    # Only the read side is asserted: PutEmailIdentityDkimAttributes on a deleted identity does not
    # fail on AWS, it silently re-creates a bare identity.
    try:
        v2.get_email_identity(EmailIdentity=dom_v2)
        raise AssertionError(f"v2 GetEmailIdentity must NotFoundException for {dom_v2!r}, which it just deleted")
    except ClientError as exc:
        code = exc.response['Error']['Code']
        message = exc.response['Error'].get('Message')
        assert code == 'NotFoundException', (
            f"expected NotFoundException reading the deleted identity {dom_v2!r}, got {code!r}: {message!r}"
        )
        assert message == f"Email identity <{dom_v2}> does not exist.", (
            f"the NotFoundException must name the deleted identity {dom_v2!r}, got {message!r}"
        )

    # Control: the delete was scoped -- the v1-created identities are untouched.
    assert v2.get_email_identity(EmailIdentity=dom_v1)['IdentityType'] == 'DOMAIN', (
        'control: deleting one identity must not remove the others'
    )
    assert v2.get_email_identity(EmailIdentity=email_v1)['IdentityType'] == 'EMAIL_ADDRESS', (
        'control: deleting one identity must not remove the others'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
