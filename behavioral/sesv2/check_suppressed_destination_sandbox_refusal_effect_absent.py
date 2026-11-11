"""suppressed-destination-sandbox-refusal-effect-absent."""
from __future__ import annotations

import datetime

CHECK = "suppressed-destination-sandbox-refusal-effect-absent"
GROUP = 'suppression'
SERVICES = ['sesv2']

from behavioral_harness import tags
from botocore.exceptions import ClientError

_MAX_PAGES = 60


def _client_error(fn) -> ClientError:
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError('expected the call to be refused, but it succeeded')


def _list_suppressed(ses, **kwargs):
    """Walk ListSuppressedDestinations to exhaustion, returning the addresses."""
    found, token = [], None
    for _ in range(_MAX_PAGES):
        call = dict(kwargs)
        if token is not None:
            call['NextToken'] = token
        resp = ses.list_suppressed_destinations(**call)
        assert 'SuppressedDestinationSummaries' in resp, (
            f"ListSuppressedDestinations must always return the SuppressedDestinationSummaries member, "
            f"got keys {sorted(resp)}"
        )
        found.extend(s['EmailAddress'] for s in resp['SuppressedDestinationSummaries'])
        token = resp.get('NextToken')
        if not token:
            return found
    raise AssertionError(f'more than {_MAX_PAGES} pages of suppressed destinations in this account')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A sandboxed account's PutSuppressedDestination is refused with the sandbox message and the
    address stays unsuppressed; an inverted date window gets its own refusal and reads still work.
    """
    # Reads only: PutAccountSuppressionAttributes / PutConfigurationSetSuppressionOptions would disable
    # a safeguard.
    ses = ctx.client('sesv2')

    acct = ses.get_account()
    assert 'ProductionAccessEnabled' in acct, f"GetAccount must report ProductionAccessEnabled, got {sorted(acct)}"
    if acct['ProductionAccessEnabled']:
        raise AssertionError(
            'this account has production access, so PutSuppressedDestination is permitted and the invariant '
            'under test (the sandbox refusal) does not apply: this check needs an account in the SES sandbox.'
        )

    # No mail is sent, so an RFC 2606 reserved domain is used rather than a mailbox-simulator address.
    addr = f"sim2real-behav-supp@{ctx.unique_name('sim2real-behav-supp-')}.example.com"
    pre = _client_error(lambda: ses.get_suppressed_destination(EmailAddress=addr))
    not_suppressed = f"Email address {addr} does not exist on your suppression list."
    assert pre.response['Error']['Code'] == 'NotFoundException', (
        f"setup precondition: {addr!r} must not be suppressed yet, got {pre.response['Error']!r}"
    )
    assert pre.response['Error'].get('Message') == not_suppressed, (
        f"setup precondition: expected {not_suppressed!r}, got {pre.response['Error']!r}"
    )

    err = _client_error(lambda: ses.put_suppressed_destination(EmailAddress=addr, Reason='BOUNCE'))
    code = err.response['Error']['Code']
    msg = err.response['Error'].get('Message') or ''
    assert code == 'BadRequestException', (
        f"a sandboxed PutSuppressedDestination must be refused with BadRequestException, got {code!r}: {msg!r}"
    )
    assert msg == 'Your account is still in the sandbox.', (
        "the refusal must say why -- real AWS answers 'Your account is still in the sandbox.' (captured in "
        f"wire/sesv2/send-email-and-suppression-list-management.json step 6); got {msg!r}"
    )

    post = _client_error(lambda: ses.get_suppressed_destination(EmailAddress=addr))
    assert post.response['Error']['Code'] == 'NotFoundException', (
        f"a refused PutSuppressedDestination must leave the address unsuppressed, got {post.response['Error']!r}"
    )
    assert post.response['Error'].get('Message') == not_suppressed, (
        f"a refused PutSuppressedDestination must leave the address unsuppressed: expected {not_suppressed!r}, "
        f"got {post.response['Error']!r}"
    )
    listed = _list_suppressed(ses)
    assert addr not in listed, (
        f"a refused PutSuppressedDestination must not add {addr!r} to the suppression list; list holds "
        f"{len(listed)} entries and includes it"
    )

    # A distinct read-path rejection proves arguments are evaluated, not one canned 400.
    err_range = _client_error(lambda: ses.list_suppressed_destinations(
        StartDate=datetime.datetime(2026, 6, 1), EndDate=datetime.datetime(2026, 1, 1)))
    assert err_range.response['Error']['Code'] == 'BadRequestException', (
        f"EndDate before StartDate must be refused with BadRequestException, got {err_range.response['Error']!r}"
    )
    expected_range = 'Start date 2026-06-01T00:00 must be before end date 2026-01-01T00:00'
    assert err_range.response['Error'].get('Message') == expected_range, (
        f"expected {expected_range!r} for an inverted window, got {err_range.response['Error']!r}"
    )
    assert (err_range.response['Error'].get('Message') or '') != msg, (
        'an inverted date range and a sandbox restriction are different conditions and must not collapse '
        f"into one byte-identical BadRequestException; both said {msg!r}"
    )

    filtered = _list_suppressed(ses, Reasons=['BOUNCE'])
    assert addr not in filtered, f"{addr!r} must not appear under a BOUNCE-filtered read either"
    supp_attrs = ses.get_account().get('SuppressionAttributes')
    assert supp_attrs is not None and 'SuppressedReasons' in supp_attrs, (
        f"GetAccount must expose the account suppression configuration, got {supp_attrs!r}"
    )
    assert isinstance(supp_attrs['SuppressedReasons'], list), (
        f"SuppressedReasons must be a list, got {supp_attrs['SuppressedReasons']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
