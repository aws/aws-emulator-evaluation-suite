"""byodkim-external-signing-attributes-rejected."""
from __future__ import annotations

CHECK = "byodkim-external-signing-attributes-rejected"
GROUP = 'identity-v2'
SERVICES = ['sesv2']

from behavioral_harness import tags
from botocore.exceptions import ClientError


def _client_error(fn) -> ClientError:
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError('expected the call to be refused, but it succeeded')


def _unique_domain(ctx, prefix='byodkim-') -> str:
    # RFC 2606 reserved domain only.
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}.example.com"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BYODKIM refuses a non-RSA private key and an illegal selector with distinct exact messages,
    leaving the identity on Easy DKIM with its tokens; an AWS_SES control still succeeds.
    """
    ses = ctx.client('sesv2')
    domain = _unique_domain(ctx)
    ses.create_email_identity(
        EmailIdentity=domain,
        Tags=[{'Key': 'sim2real-check', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda _d=domain: ses.delete_email_identity(EmailIdentity=_d))

    before = ses.get_email_identity(EmailIdentity=domain)['DkimAttributes']
    assert before.get('SigningAttributesOrigin') == 'AWS_SES', (
        f"setup precondition: fresh identity must be on Easy DKIM, got {before!r}"
    )
    easy_tokens = set(before.get('Tokens') or [])
    assert len(easy_tokens) == 3, f"setup precondition: expected 3 Easy DKIM tokens, got {before.get('Tokens')!r}"

    # Well-formed base64 that is not an RSA private key; botocore does not validate pattern/max,
    # so these malformed values reach the server.
    not_a_key = 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk='
    err_key = _client_error(lambda: ses.put_email_identity_dkim_signing_attributes(
        EmailIdentity=domain,
        SigningAttributesOrigin='EXTERNAL',
        SigningAttributes={'DomainSigningSelector': 'sim2real1', 'DomainSigningPrivateKey': not_a_key},
    ))
    code_key = err_key.response['Error']['Code']
    msg_key = err_key.response['Error'].get('Message') or ''
    assert code_key == 'BadRequestException', (
        f"a non-RSA BYODKIM private key must be refused with BadRequestException, got {code_key!r}: {msg_key!r}"
    )
    expected_key_msg = 'Please provide a valid DomainSigningSelector and DomainSigningPrivateKey.'
    assert msg_key == expected_key_msg, (
        f"a non-RSA BYODKIM private key must be refused with {expected_key_msg!r}, got {msg_key!r}"
    )

    # Break a different single thing: the selector violates the modeled Selector pattern
    # ^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]))$ (underscores are not permitted).
    err_sel = _client_error(lambda: ses.put_email_identity_dkim_signing_attributes(
        EmailIdentity=domain,
        SigningAttributesOrigin='EXTERNAL',
        SigningAttributes={'DomainSigningSelector': '_bad_selector_', 'DomainSigningPrivateKey': not_a_key},
    ))
    code_sel = err_sel.response['Error']['Code']
    msg_sel = err_sel.response['Error'].get('Message') or ''
    assert code_sel == 'BadRequestException', (
        f"an illegal DKIM selector must be refused with BadRequestException, got {code_sel!r}: {msg_sel!r}"
    )
    expected_sel_msg = (
        "1 validation error detected: Value at 'signingAttributes.domainSigningSelector' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: "
        "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9]))$"
    )
    assert msg_sel == expected_sel_msg, (
        f"an illegal DKIM selector must be refused with {expected_sel_msg!r}, got {msg_sel!r}"
    )
    assert msg_sel != msg_key, (
        'an illegal selector and a malformed private key are different conditions and must not collapse '
        f"into one byte-identical refusal; both said {msg_key!r}"
    )

    after = ses.get_email_identity(EmailIdentity=domain)['DkimAttributes']
    assert after.get('SigningAttributesOrigin') == 'AWS_SES', (
        f"refused BYODKIM calls must not change SigningAttributesOrigin, got {after.get('SigningAttributesOrigin')!r}"
    )
    assert set(after.get('Tokens') or []) == easy_tokens, (
        f"refused BYODKIM calls must not rotate the Easy DKIM tokens: before={sorted(easy_tokens)} "
        f"after={sorted(after.get('Tokens') or [])}"
    )
    assert after.get('Status') == 'PENDING', (
        f"refused BYODKIM calls must not change DKIM status, got {after.get('Status')!r}"
    )

    # Control: the refusals above are about the input, not an unimplemented operation.
    ok = ses.put_email_identity_dkim_signing_attributes(
        EmailIdentity=domain,
        SigningAttributesOrigin='AWS_SES',
        SigningAttributes={'NextSigningKeyLength': 'RSA_2048_BIT'},
    )
    ok_tokens = ok.get('DkimTokens') or []
    assert len(ok_tokens) == 3 and len(set(ok_tokens)) == 3, (
        f"the AWS_SES control must return three distinct tokens, got {ok_tokens!r}"
    )
    control = ses.get_email_identity(EmailIdentity=domain)['DkimAttributes']
    assert control.get('SigningAttributesOrigin') == 'AWS_SES', (
        f"control: origin must remain AWS_SES, got {control.get('SigningAttributesOrigin')!r}"
    )
    assert set(control.get('Tokens') or []) == set(ok_tokens), (
        f"control: GetEmailIdentity must serve the tokens the Put returned: "
        f"put={sorted(ok_tokens)} get={sorted(control.get('Tokens') or [])}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
