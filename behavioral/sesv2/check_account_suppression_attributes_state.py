"""account-suppression-attributes-state."""
from __future__ import annotations
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "account-suppression-attributes-state"
GROUP = 'suppression'
SERVICES = ['sesv2']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ses-account")
def run(ctx) -> None:
    """PutAccountSuppressionAttributes replaces (not merges) the account reason set and GetAccount
    reflects each change; a never-suppressed address is NotFound, with a PutSuppressedDestination
    control that either succeeds or is refused in the sandbox without effect.
    """
    ses = ctx.client('sesv2')
    original = ses.get_account().get('SuppressionAttributes', {}).get('SuppressedReasons', [])
    try:
        ses.put_account_suppression_attributes(SuppressedReasons=['BOUNCE'])
        _deadline = time.monotonic() + 30
        got = None
        while time.monotonic() < _deadline:
            got = ses.get_account()
            if set(got.get('SuppressionAttributes', {}).get('SuppressedReasons', [])) == {'BOUNCE'}:
                break
            time.sleep(2)
        else:
            raise AssertionError('condition not met within ' + str(30) + 's. Last result: ' + repr(got))
        assert set(got['SuppressionAttributes']['SuppressedReasons']) == {'BOUNCE'}, \
            f"expected {{'BOUNCE'}}, got {got['SuppressionAttributes']['SuppressedReasons']}"
        ses.put_account_suppression_attributes(SuppressedReasons=['BOUNCE', 'COMPLAINT'])
        _deadline = time.monotonic() + 30
        got2 = None
        while time.monotonic() < _deadline:
            got2 = ses.get_account()
            if set(got2.get('SuppressionAttributes', {}).get('SuppressedReasons', [])) == {'BOUNCE', 'COMPLAINT'}:
                break
            time.sleep(2)
        else:
            raise AssertionError('condition not met within ' + str(30) + 's. Last result: ' + repr(got2))
        assert set(got2['SuppressionAttributes']['SuppressedReasons']) == {'BOUNCE', 'COMPLAINT'}, \
            f"expected {{'BOUNCE', 'COMPLAINT'}}, got {got2['SuppressionAttributes']['SuppressedReasons']}"

        ses.put_account_suppression_attributes(SuppressedReasons=['COMPLAINT'])
        _deadline = time.monotonic() + 30
        got3 = None
        while time.monotonic() < _deadline:
            got3 = ses.get_account()
            if set(got3.get('SuppressionAttributes', {}).get('SuppressedReasons', [])) == {'COMPLAINT'}:
                break
            time.sleep(2)
        else:
            raise AssertionError('condition not met within ' + str(30) + 's. Last result: ' + repr(got3))
        assert set(got3['SuppressionAttributes']['SuppressedReasons']) == {'COMPLAINT'}, \
            f"Put replaces rather than merges the reason set: expected {{'COMPLAINT'}}, got {got3['SuppressionAttributes']['SuppressedReasons']}"

        control_address = ctx.unique_name('sim2real-behav-account-suppress-ctrl-') + '@example.com'
        _control_state = {'deleted': False}
        try:
            ses.put_suppressed_destination(EmailAddress=control_address, Reason='BOUNCE')
        except ClientError as _e:
            _err = _e.response.get('Error', {})
            assert (_err.get('Code'), _err.get('Message')) == ('BadRequestException', 'Your account is still in the sandbox.'), \
                f"expected the SES-sandbox refusal on PutSuppressedDestination, got {_err.get('Code')}: {_err.get('Message')}"
            # Sandbox accounts are refused PutSuppressedDestination; the refusal must leave no effect.
            control_err = _error(lambda: ses.get_suppressed_destination(EmailAddress=control_address))
            expected_control = ('NotFoundException', f'Email address {control_address} does not exist on your suppression list.')
            assert control_err == expected_control, \
                f"sandbox-refused Put must have no effect: expected {expected_control}, got {control_err}"
        else:
            # With production access, a found result makes the NotFound assertion below meaningful.
            ctx.on_cleanup(lambda: None if _control_state['deleted'] else ses.delete_suppressed_destination(EmailAddress=control_address))
            control_fetched = ses.get_suppressed_destination(EmailAddress=control_address)['SuppressedDestination']
            assert control_fetched['Reason'] == 'BOUNCE', \
                f"positive control: expected GetSuppressedDestination to report BOUNCE, got {control_fetched.get('Reason')}"
            ses.delete_suppressed_destination(EmailAddress=control_address)
            _control_state['deleted'] = True

        never = ctx.unique_name('sim2real-behav-never-suppressed-') + '@example.com'
        never_err = _error(lambda: ses.get_suppressed_destination(EmailAddress=never))
        expected_never = ('NotFoundException', f'Email address {never} does not exist on your suppression list.')
        assert never_err == expected_never, f'expected {expected_never}, got {never_err}'
    finally:
        ses.put_account_suppression_attributes(SuppressedReasons=original)


def _error(fn):
    """Return the (code, message) of the ClientError fn raises; raise if fn succeeds."""
    try:
        result = fn()
    except ClientError as _e:
        _err = _e.response.get('Error', {})
        return (_err.get('Code'), _err.get('Message'))
    raise AssertionError(f'expected a ClientError, the call succeeded with {result!r}')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
