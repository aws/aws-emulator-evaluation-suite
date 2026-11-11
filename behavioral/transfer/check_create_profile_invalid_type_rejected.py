"""create-profile-invalid-type-rejected."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "create-profile-invalid-type-rejected"
GROUP = 'overly-permissive'
SERVICES = ['transfer']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateProfile with ProfileType BOGUS fails with ValidationException and the exact enum-constraint message and
    adds no profile to ListProfiles, while a LOCAL profile is created and listed.
    """
    tf = ctx.client('transfer')

    bad_as2_id = ctx.unique_name('sim2real-behav-as2-bad-')
    error = _client_error(lambda: tf.create_profile(As2Id=bad_as2_id, ProfileType='BOGUS'))
    assert error == ('ValidationException', "1 validation error detected: Value at 'profileType' failed to satisfy constraint: Member must satisfy enum value set: [PARTNER, LOCAL]"), error

    after_reject = _profile_ids_with_as2_id(tf, bad_as2_id)
    assert after_reject == [], f"a profile was created despite the invalid ProfileType: {after_reject}"

    good_as2_id = ctx.unique_name('sim2real-behav-as2-good-')
    pid = tf.create_profile(
        As2Id=good_as2_id, ProfileType='LOCAL', Tags=[{'Key': 'sim2real', 'Value': CHECK}]
    )['ProfileId']
    ctx.on_cleanup(lambda: tf.delete_profile(ProfileId=pid))

    after_control = _profile_ids_with_as2_id(tf, good_as2_id)
    assert after_control == [pid], after_control


def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so a target
    that accepts what AWS refuses cannot read as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _profile_ids_with_as2_id(tf, as2_id):
    """Every listed profile id carrying as2_id, across all pages."""
    ids = []
    kwargs: dict = {}
    while True:
        resp = tf.list_profiles(**kwargs)
        ids.extend(p['ProfileId'] for p in resp.get('Profiles', []) if p.get('As2Id') == as2_id)
        token = resp.get('NextToken')
        if not token:
            break
        kwargs = {'NextToken': token}
    return sorted(ids)


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
