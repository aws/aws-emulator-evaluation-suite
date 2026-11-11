"""send-unverified-identity-rejected-quota-unchanged."""
from __future__ import annotations

CHECK = "send-unverified-identity-rejected-quota-unchanged"
GROUP = 'overly-permissive'
SERVICES = ['ses']

from behavioral_harness import tags
from botocore.exceptions import ClientError

# The mailbox simulator keeps a wrongly accepted send out of any real inbox. `success@` rather than
# `bounce@`/`complaint@` because simulated bounces and complaints count against sender reputation.
_SIMULATOR_TO = 'success@simulator.amazonses.com'


def _client_error(fn) -> ClientError:
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError('expected the send to be refused, but it was accepted')


# The refusal a send meets while the account's sending is paused, per API.
_PAUSED_CODE = {"ses": "AccountSendingPausedException", "sesv2": "SendingPausedException"}


def _send_refusal(ctx, api: str, send, own_code: str):
    """Run ``send`` between two GetAccountSendingEnabled reads; return its ClientError (None on
    success) and the codes it may carry: ``own_code`` while sending is enabled, the paused refusal
    while it is paused, and either when the state changes in between."""
    account = ctx.client("ses")
    before = account.get_account_sending_enabled()["Enabled"]
    try:
        send()
        err = None
    except ClientError as exc:
        err = exc
    after = account.get_account_sending_enabled()["Enabled"]
    return err, {own_code if enabled else _PAUSED_CODE[api] for enabled in (before, after)}


def _unique_domain(ctx, prefix='unverif-') -> str:
    # RFC 2606 reserved domain only.
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}.example.com"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A send from an unverified identity is refused with MessageRejected naming that identity;
    the 24-hour send counter does not move and the attempt does not verify the identity.
    """
    v2 = ctx.client('sesv2')
    v1 = ctx.client('ses')

    created = f"sim2real-behav-sender@{_unique_domain(ctx)}"
    v2.create_email_identity(EmailIdentity=created, Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda _e=created: v2.delete_email_identity(EmailIdentity=_e))
    ident = v2.get_email_identity(EmailIdentity=created)
    assert ident['VerifiedForSendingStatus'] is False, (
        f"setup precondition: {created!r} must not be verified, got {ident.get('VerifiedForSendingStatus')!r}"
    )

    acct_before = v2.get_account()
    quota_before = acct_before['SendQuota']
    sent_before = quota_before['SentLast24Hours']
    max_before = quota_before['Max24HourSend']
    v1_sent_before = v1.get_send_quota()['SentLast24Hours']

    err_v2, allowed_v2 = _send_refusal(ctx, 'sesv2', lambda: v2.send_email(
        FromEmailAddress=created,
        Destination={'ToAddresses': [_SIMULATOR_TO]},
        Content={'Simple': {
            'Subject': {'Data': 'sim2real unverified-sender probe'},
            'Body': {'Text': {'Data': 'This send must be refused.'}},
        }},
    ), 'MessageRejected')
    assert err_v2 is not None, 'expected the send to be refused, but it was accepted'
    code_v2 = err_v2.response['Error']['Code']
    msg_v2 = err_v2.response['Error'].get('Message') or ''
    assert code_v2 in allowed_v2, (
        f"a send from an unverified identity must be refused with {sorted(allowed_v2)}, got {code_v2!r}: {msg_v2!r}"
    )
    created_msg = (
        "Email address is not verified. The following identities failed the check in region "
        f"{ctx.region.upper()}: {created}"
    )
    if code_v2 == 'MessageRejected':
        assert msg_v2 == created_msg, (
            f"AWS names the failing identity in the MessageRejected message; a generic refusal hides which "
            f"identity was at fault. Expected {created_msg!r}, got {msg_v2!r}"
        )

    # A second, never-created sender must get its own message, not one canned string.
    never_created = f"sim2real-behav-ghost@{_unique_domain(ctx, 'ghost-')}"
    err_v1, allowed_v1 = _send_refusal(ctx, 'ses', lambda: v1.send_email(
        Source=never_created,
        Destination={'ToAddresses': [_SIMULATOR_TO]},
        Message={
            'Subject': {'Data': 'sim2real unverified-sender probe v1'},
            'Body': {'Text': {'Data': 'This send must be refused.'}},
        },
    ), 'MessageRejected')
    assert err_v1 is not None, 'expected the v1 send to be refused, but it was accepted'
    code_v1 = err_v1.response['Error']['Code']
    msg_v1 = err_v1.response['Error'].get('Message') or ''
    assert code_v1 in allowed_v1, (
        f"v1 SendEmail from an unverified source must be refused with {sorted(allowed_v1)}, got {code_v1!r}: {msg_v1!r}"
    )
    if code_v1 == 'MessageRejected':
        ghost_msg = (
            "Email address is not verified. The following identities failed the check in region "
            f"{ctx.region.upper()}: {never_created}"
        )
    else:
        ghost_msg = 'Sending is paused for this account.'
    assert msg_v1 == ghost_msg, (
        f"expected the v1 refusal {ghost_msg!r}, got {msg_v1!r}"
    )
    if code_v1 == code_v2 == 'MessageRejected':
        assert msg_v1 != msg_v2, (
            'two different unverified senders must not collapse into one byte-identical MessageRejected '
            f"message; both said {msg_v2!r}"
        )

    quota_after = v2.get_account()['SendQuota']
    delta = quota_after['SentLast24Hours'] - sent_before
    assert delta < 1.0, (
        f"a refused send must not be counted: SentLast24Hours moved by {delta} "
        f"({sent_before} -> {quota_after['SentLast24Hours']})"
    )
    assert quota_after['Max24HourSend'] == max_before, (
        f"a refused send must not change the sending limit: {max_before} -> {quota_after['Max24HourSend']}"
    )
    v1_delta = v1.get_send_quota()['SentLast24Hours'] - v1_sent_before
    assert v1_delta < 1.0, (
        f"v1 GetSendQuota must agree that nothing was sent, moved by {v1_delta}"
    )

    still = v2.get_email_identity(EmailIdentity=created)
    assert still['VerifiedForSendingStatus'] is False, (
        f"a refused send must not verify the sender, got {still.get('VerifiedForSendingStatus')!r}"
    )
    v1_attrs = v1.get_identity_verification_attributes(Identities=[created])['VerificationAttributes']
    assert v1_attrs[created]['VerificationStatus'] == 'Pending', (
        f"v1 must still report the identity Pending, got {v1_attrs[created]!r}"
    )

    # 'Unverified' and 'does not exist' are distinct states when read rather than sent from.
    absent = f"sim2real-behav-absent@{_unique_domain(ctx, 'absent-')}"
    err_absent = _client_error(lambda: v2.get_email_identity(EmailIdentity=absent))
    assert err_absent.response['Error']['Code'] == 'NotFoundException', (
        f"reading a never-created identity must be NotFoundException, got "
        f"{err_absent.response['Error']['Code']!r}"
    )
    absent_msg = f"Email identity <{absent}> does not exist."
    assert err_absent.response['Error'].get('Message') == absent_msg, (
        f"expected {absent_msg!r}, got {err_absent.response['Error'].get('Message')!r}"
    )
    assert v2.get_email_identity(EmailIdentity=created)['IdentityType'] == 'EMAIL_ADDRESS', (
        'control: the unverified identity must still be readable after the refused sends'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
