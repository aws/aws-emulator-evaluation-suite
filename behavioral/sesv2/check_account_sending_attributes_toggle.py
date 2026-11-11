"""account-sending-attributes-toggle."""
from __future__ import annotations
import time

from behavioral_harness import tags
CHECK = "account-sending-attributes-toggle"
GROUP = 'account'
SERVICES = ['sesv2']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ses-account")
def run(ctx) -> None:
    """PutAccountSendingAttributes(disable) -> GetAccount reflects -> re-enable restores."""
    ses = ctx.client('sesv2')
    original = ses.get_account()
    original_enabled = original.get('SendingEnabled', True)
    try:
        ses.put_account_sending_attributes(SendingEnabled=False)
        _deadline = time.monotonic() + 20
        got = None
        while time.monotonic() < _deadline:
            got = ses.get_account()
            if got.get('SendingEnabled') is False:
                break
            time.sleep(1)
        else:
            raise AssertionError('condition not met within ' + str(20) + 's. Last result: ' + repr(got))
        assert got.get('SendingEnabled') is False, got.get('SendingEnabled')
    finally:
        ses.put_account_sending_attributes(SendingEnabled=original_enabled)
    _deadline = time.monotonic() + 20
    restored = None
    while time.monotonic() < _deadline:
        restored = ses.get_account()
        if restored.get('SendingEnabled') is original_enabled:
            break
        time.sleep(1)
    else:
        raise AssertionError('restore to original SendingEnabled=' + repr(original_enabled) + ' not met within ' + str(20) + 's. Last result: ' + repr(restored))
    assert restored.get('SendingEnabled') is original_enabled, (original_enabled, restored.get('SendingEnabled'))
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
