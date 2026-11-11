"""delete-profile-not-found."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "delete-profile-not-found"
GROUP = 'error-semantics'
SERVICES = ['transfer']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteProfile on a well-formed, never-created ProfileId fails with ResourceNotFoundException
    "Unknown profile", while deleting a profile the check created succeeds.
    """
    tf = ctx.client('transfer')
    as2_id = ctx.unique_name('sim2real-behav-as2-')
    real_id = tf.create_profile(As2Id=as2_id, ProfileType='LOCAL')['ProfileId']

    def _cleanup():
        try:
            tf.delete_profile(ProfileId=real_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    ctx.on_cleanup(_cleanup)

    # Positive control: DeleteProfile succeeds on a profile that really exists.
    tf.delete_profile(ProfileId=real_id)

    # A well-formed id in the same shape, never created, must be rejected
    # specifically — not merely because every DeleteProfile call fails.
    bogus_id = real_id[:-1] + ('1' if real_id[-1] != '1' else '2')
    try:
        tf.delete_profile(ProfileId=bogus_id)
    except ClientError as _e:
        code = _e.response.get('Error', {}).get('Code')
        message = _e.response.get('Error', {}).get('Message')
    else:
        raise AssertionError(f"expected DeleteProfile({bogus_id!r}) to be rejected, but it succeeded")
    assert code == 'ResourceNotFoundException', f"expected ResourceNotFoundException, got {code}"
    assert message == 'Unknown profile', f"unexpected not-found message: {message!r}"
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
