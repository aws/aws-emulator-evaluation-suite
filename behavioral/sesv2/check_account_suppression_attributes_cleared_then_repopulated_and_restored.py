"""account-suppression-attributes-cleared-then-repopulated-and-restored."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "account-suppression-attributes-cleared-then-repopulated-and-restored"
GROUP = 'account-v2'
SERVICES = ['sesv2']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ses-account")
def run(ctx) -> None:
    """PutAccountSuppressionAttributes([]) leaves GetAccount's SuppressedReasons a real empty
    list that a further Put can repopulate, and the account's prior reasons are restored after.
    """
    ses = ctx.client('sesv2')
    original = ses.get_account()['SuppressionAttributes']['SuppressedReasons']
    try:
        ses.put_account_suppression_attributes(SuppressedReasons=['BOUNCE', 'COMPLAINT'])
        seeded = ses.get_account()['SuppressionAttributes']['SuppressedReasons']
        assert set(seeded) == {'BOUNCE', 'COMPLAINT'} and len(seeded) == 2, (
            f"expected exactly ['BOUNCE', 'COMPLAINT'], got {seeded!r}"
        )

        ses.put_account_suppression_attributes(SuppressedReasons=[])
        cleared = ses.get_account()['SuppressionAttributes']['SuppressedReasons']
        assert cleared == [], f"expected an empty list after clearing, got {cleared!r}"

        ses.put_account_suppression_attributes(SuppressedReasons=['BOUNCE'])
        refilled = ses.get_account()['SuppressionAttributes']['SuppressedReasons']
        assert refilled == ['BOUNCE'], (
            f"expected exactly ['BOUNCE'] after a put onto the cleared list, got {refilled!r}"
        )
    finally:
        ses.put_account_suppression_attributes(SuppressedReasons=original)

    restored = ses.get_account()['SuppressionAttributes']['SuppressedReasons']
    assert set(restored) == set(original) and len(restored) == len(original), (
        f"expected the original reasons {original!r} restored, got {restored!r}"
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
