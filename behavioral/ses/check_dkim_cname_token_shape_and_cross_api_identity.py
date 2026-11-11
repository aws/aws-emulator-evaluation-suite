"""dkim-cname-token-shape-and-cross-api-identity."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "dkim-cname-token-shape-and-cross-api-identity"
GROUP = 'identity-v2'
SERVICES = ['ses']

# A DKIM token is published as the left-most label of `<token>._domainkey.<domain>`, so it must
# be a legal DNS label: lowercase, alphanumeric-or-hyphen, 1..63 chars, no leading/trailing hyphen.
_DNS_LABEL_RE = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')


def _unique_domain(ctx, prefix='dkim-') -> str:
    # RFC 2606 reserved domain only -- never a real or Amazon-owned domain.
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}.example.com"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Easy DKIM on a fresh domain identity yields three distinct 32-character DNS-label tokens that
    v1 GetIdentityDkimAttributes reports identically; an email-address identity gets none.
    """
    v2 = ctx.client('sesv2')
    v1 = ctx.client('ses')

    domain = _unique_domain(ctx)
    v2.create_email_identity(EmailIdentity=domain, Tags=[{'Key': 'sim2real-role', 'Value': 'dkim-token-shape'}])
    ctx.on_cleanup(lambda _d=domain: v2.delete_email_identity(EmailIdentity=_d))

    got = v2.get_email_identity(EmailIdentity=domain)
    assert got['IdentityType'] == 'DOMAIN', (
        f"IdentityType must be derived from the identity string, got {got.get('IdentityType')!r} for {domain!r}"
    )
    assert got['VerifiedForSendingStatus'] is False, (
        f"a brand-new domain identity cannot be verified for sending, got {got.get('VerifiedForSendingStatus')!r}"
    )

    dkim = got['DkimAttributes']
    assert dkim.get('SigningAttributesOrigin') == 'AWS_SES', (
        f"a fresh identity must default to Easy DKIM (AWS_SES), got {dkim.get('SigningAttributesOrigin')!r}"
    )
    assert dkim.get('Status') == 'PENDING', (
        f"Easy DKIM must start PENDING until the CNAMEs resolve, got {dkim.get('Status')!r}"
    )
    assert dkim.get('SigningEnabled') is True, (
        f"Easy DKIM signing is enabled by default, got {dkim.get('SigningEnabled')!r}"
    )

    tokens = dkim.get('Tokens')
    assert isinstance(tokens, list) and len(tokens) == 3, (
        f"Easy DKIM publishes exactly three CNAME tokens, got {tokens!r}"
    )
    assert len(set(tokens)) == 3, f"the three DKIM tokens must be distinct, got {tokens!r}"
    for tok in tokens:
        assert _DNS_LABEL_RE.match(tok), (
            f"DKIM token {tok!r} is not a legal DNS label and cannot be published as "
            f"'{tok}._domainkey.{domain}'"
        )
        record_name = f"{tok}._domainkey.{domain}"
        assert len(record_name) <= 255, f"CNAME record name exceeds 255 octets: {record_name!r}"
        assert len(tok) == 32, f"Easy DKIM tokens are 32 characters, got {len(tok)} in {tok!r}"

    v1_dkim = v1.get_identity_dkim_attributes(Identities=[domain])['DkimAttributes'][domain]
    assert v1_dkim.get('DkimEnabled') is True, (
        f"v1 must report Easy DKIM enabled for a v2-created identity, got {v1_dkim!r}"
    )
    assert v1_dkim.get('DkimVerificationStatus') == 'Pending', (
        f"v1 DkimVerificationStatus must mirror v2 PENDING as 'Pending', got "
        f"{v1_dkim.get('DkimVerificationStatus')!r}"
    )
    assert set(v1_dkim.get('DkimTokens') or []) == set(tokens), (
        f"v1 and v2 must serve the same DKIM tokens from one store: v1={v1_dkim.get('DkimTokens')!r} "
        f"v2={tokens!r}"
    )

    # Control: an EMAIL_ADDRESS identity has no domain to publish CNAMEs in, so it gets no tokens.
    email = f"sim2real-behav-dkim@{_unique_domain(ctx, 'dkimctl-')}"
    v2.create_email_identity(EmailIdentity=email, Tags=[{'Key': 'sim2real-role', 'Value': 'dkim-token-shape'}])
    ctx.on_cleanup(lambda _e=email: v2.delete_email_identity(EmailIdentity=_e))
    got_email = v2.get_email_identity(EmailIdentity=email)
    assert got_email['IdentityType'] == 'EMAIL_ADDRESS', (
        f"IdentityType for {email!r} must derive to EMAIL_ADDRESS, got {got_email.get('IdentityType')!r}"
    )
    email_tokens = (got_email.get('DkimAttributes') or {}).get('Tokens') or []
    assert not email_tokens, (
        f"an email-address identity has no Easy DKIM CNAMEs to publish, got tokens {email_tokens!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
