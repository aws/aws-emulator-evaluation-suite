"""send-email-unverified-sender-rejected."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "send-email-unverified-sender-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sesv2']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data", "requires:dns-baseline")
def run(ctx) -> None:
    """SendEmail from an unverified identity is rejected with MessageRejected and the exact not-verified message
    naming that address, while the identical call from a verified identity succeeds, so the gate is sender
    verification.
    """
    ses = ctx.client('sesv2')
    content = {'Simple': {'Subject': {'Data': 'Test subject'}, 'Body': {'Text': {'Data': 'Test body'}}}}

    verified_sender = _find_verified_sender(ses)
    if verified_sender is None:
        raise AssertionError(
            'no verified SES sending identity exists; SendEmail requires a '
            'verified FROM identity even to send to the mailbox-simulator recipient'
        )
    control = ses.send_email(
        FromEmailAddress=verified_sender,
        Destination={'ToAddresses': ['success@simulator.amazonses.com']},
        Content=content,
    )
    assert control['MessageId'], 'send_email from a verified sender returned no MessageId'

    unverified = ctx.unique_name('sim2real-behav-unverified-sender-') + '@example.com'
    try:
        ses.send_email(FromEmailAddress=unverified, Destination={'ToAddresses': ['success@simulator.amazonses.com']}, Content=content)
        err = None
    except ClientError as _e:
        err = (_e.response.get('Error', {}).get('Code'), _e.response.get('Error', {}).get('Message'))
    expected = (
        'MessageRejected',
        'Email address is not verified. The following identities failed the check in region '
        f'{ses.meta.region_name.upper()}: {unverified}',
    )
    assert err == expected, f'expected {expected!r}, got {err!r}'


# ===== helpers =====
def _find_verified_sender(ses):
    next_token = None
    while True:
        kwargs = {'NextToken': next_token} if next_token else {}
        resp = ses.list_email_identities(**kwargs)
        for identity in resp.get('EmailIdentities', []):
            if identity.get('VerificationStatus') == 'SUCCESS' and identity.get('SendingEnabled', True):
                name = identity['IdentityName']
                if identity.get('IdentityType') == 'DOMAIN':
                    return f'sim2real-check@{name}'
                return name
        next_token = resp.get('NextToken')
        if not next_token:
            return None


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
