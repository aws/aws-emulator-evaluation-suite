"""email-identity-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "email-identity-lifecycle"
GROUP = 'identity'
SERVICES = ['sesv2']


def _error(fn):
    """Call fn(); return its botocore Error dict plus the response's HTTPStatusCode. An unexpected SUCCESS raises, because
    an emulator that accepts a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
        return {**exc.response.get('Error', {}), 'HTTPStatusCode': status}
    raise AssertionError(f'expected the call to fail, but it succeeded and returned {result!r}')


def _list_identities(ses) -> list:
    """Every IdentityName ListEmailIdentities returns, across pages."""
    listed, token = [], None
    while True:
        page = ses.list_email_identities(NextToken=token) if token else ses.list_email_identities()
        listed.extend(i.get('IdentityName') for i in page.get('EmailIdentities', []))
        token = page.get('NextToken')
        if not token:
            return listed


def _ignore_not_found(fn):
    """Teardown helper: a resource the check already deleted reads as not-found."""
    try:
        fn()
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """create -> get(reflects identity type / verification / dkim) -> delete -> delete(NotFound,
    proving the dead identity also rejects a further mutation) -> get(NotFound, terminal read)."""
    ses = ctx.client('sesv2')
    email = ctx.unique_name('sim2real-behav-identity-') + '@example.com'
    ses.create_email_identity(EmailIdentity=email, Tags=[{'Key': 'sim2real-check', 'Value': CHECK}])
    ctx.on_cleanup(lambda _k=email: _ignore_not_found(lambda: ses.delete_email_identity(EmailIdentity=_k)))
    got = ses.get_email_identity(EmailIdentity=email)
    assert got['IdentityType'] == 'EMAIL_ADDRESS', f"expected EMAIL_ADDRESS, got {got.get('IdentityType')}"
    assert 'VerifiedForSendingStatus' in got, f'missing VerifiedForSendingStatus in {got}'
    assert 'DkimAttributes' in got, f'missing DkimAttributes in {got}'
    assert email in _list_identities(ses), (
        f'a live identity {email!r} must be listed by ListEmailIdentities')
    ses.delete_email_identity(EmailIdentity=email)
    err = _error(lambda: ses.delete_email_identity(EmailIdentity=email))
    assert err.get('Code') == 'NotFoundException', f'expected NotFoundException deleting an already-deleted identity, got {err!r}'
    assert isinstance(err.get('HTTPStatusCode'), int) and 400 <= err.get('HTTPStatusCode') < 500, f'expected HTTP 4xx deleting an already-deleted identity, got {err!r}'
    expected_message = f"Email identity {email} does not exist."
    assert err.get('Message') == expected_message, f"expected the message {expected_message!r}, got {err.get('Message')!r}"
    err = _error(lambda: ses.get_email_identity(EmailIdentity=email))
    assert err.get('Code') == 'NotFoundException', f'expected NotFoundException, got {err!r}'
    assert isinstance(err.get('HTTPStatusCode'), int) and 400 <= err.get('HTTPStatusCode') < 500, f'expected HTTP 4xx from GetEmailIdentity, got {err!r}'
    expected_message = f"Email identity <{email}> does not exist."
    assert err.get('Message') == expected_message, f"expected the message {expected_message!r}, got {err.get('Message')!r}"
    assert email not in _list_identities(ses), f'deleted identity {email!r} is still listed by ListEmailIdentities'
    err = _error(lambda: ses.put_email_identity_feedback_attributes(EmailIdentity=email, EmailForwardingEnabled=True))
    assert err.get('Code') == 'BadRequestException', (
        f'expected PutEmailIdentityFeedbackAttributes on the deleted identity to be refused as '
        f'BadRequestException, got {err!r}')
    assert err.get('HTTPStatusCode') == 400, f'expected HTTP 400, got {err!r}'
    expected_message = f"Identity {email} is invalid. Must be a verified email address or domain."
    assert err.get('Message') == expected_message, f"expected the message {expected_message!r}, got {err.get('Message')!r}"

if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
