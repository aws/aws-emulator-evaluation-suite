"""account-suppression-attributes-invalid-reason-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "account-suppression-attributes-invalid-reason-rejected"
GROUP = 'account-v2'
SERVICES = ['sesv2']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ses-account")
def run(ctx) -> None:
    """PutAccountSuppressionAttributes rejects an unknown suppression reason and leaves
    GetAccount's SuppressedReasons unchanged from a prior valid value.
    """
    ses = ctx.client('sesv2')
    original = ses.get_account()['SuppressionAttributes']['SuppressedReasons']
    try:
        ses.put_account_suppression_attributes(SuppressedReasons=['BOUNCE'])
        before = ses.get_account()['SuppressionAttributes']['SuppressedReasons']
        assert before == ['BOUNCE'], f"expected ['BOUNCE'] after the positive control, got {before!r}"

        try:
            ses.put_account_suppression_attributes(SuppressedReasons=['BOUNCE', 'INVALID'])
            err = None
        except ClientError as exc:
            err = (exc.response['Error']['Code'], exc.response['Error'].get('Message'))
        expected = (
            'BadRequestException',
            "1 validation error detected: Value at 'suppressedReasons' failed to satisfy "
            "constraint: Member must satisfy constraint: "
            "[Member must satisfy enum value set: [BOUNCE, COMPLAINT]]",
        )
        assert err == expected, f'expected {expected!r} for an invalid suppression reason, got {err!r}'

        after = ses.get_account()['SuppressionAttributes']['SuppressedReasons']
        assert after == ['BOUNCE'], f"expected ['BOUNCE'] unchanged after the rejected call, got {after!r}"
    finally:
        ses.put_account_suppression_attributes(SuppressedReasons=original)

    restored = ses.get_account()['SuppressionAttributes']['SuppressedReasons']
    assert set(restored) == set(original) and len(restored) == len(original), (
        f"expected the original reasons {original!r} restored, got {restored!r}"
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
