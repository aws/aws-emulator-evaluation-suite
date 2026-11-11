"""profile-create-describe-delete."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "profile-create-describe-delete"
GROUP = 'lifecycle'
SERVICES = ['transfer']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeProfile echoes a created profile's id, ProfileType LOCAL and As2Id; after DeleteProfile both
    DescribeProfile and a second DeleteProfile fail with ResourceNotFoundException "Unknown profile".
    """
    tf = ctx.client('transfer')
    as2_id = ctx.unique_name('sim2real-behav-as2-')
    pid = tf.create_profile(
        As2Id=as2_id, ProfileType='LOCAL', Tags=[{'Key': 'Name', 'Value': as2_id}]
    )['ProfileId']
    ctx.on_cleanup(lambda _k=pid: _safe_delete_profile(tf, _k))
    prof = tf.describe_profile(ProfileId=pid)['Profile']
    assert prof['ProfileId'] == pid, prof
    assert prof['ProfileType'] == 'LOCAL', prof
    assert prof['As2Id'] == as2_id, prof

    tf.delete_profile(ProfileId=pid)

    code, msg = _err(lambda: tf.describe_profile(ProfileId=pid))
    assert code == 'ResourceNotFoundException', f'DescribeProfile after delete: expected ResourceNotFoundException, got {code}'
    assert msg == 'Unknown profile', f'DescribeProfile after delete: unexpected message {msg!r}'

    code, msg = _err(lambda: tf.delete_profile(ProfileId=pid))
    assert code == 'ResourceNotFoundException', f'second DeleteProfile: expected ResourceNotFoundException, got {code}'
    assert msg == 'Unknown profile', f'second DeleteProfile: unexpected message {msg!r}'


def _err(fn):
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _safe_delete_profile(tf, profile_id: str) -> None:
    try:
        tf.delete_profile(ProfileId=profile_id)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'ResourceNotFoundException':
            raise


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
