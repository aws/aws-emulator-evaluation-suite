"""list-profiles-reflects-created."""
from __future__ import annotations
import time

from behavioral_harness import tags
CHECK = "list-profiles-reflects-created"
GROUP = 'lifecycle'
SERVICES = ['transfer']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListProfiles surfaces both a LOCAL and a PARTNER profile this check created.

    Asserts membership of THIS check's own profile ids, never an unscoped count.
    """
    tf = ctx.client('transfer')
    local_as2 = ctx.unique_name('sim2real-behav-as2-')
    local_id = tf.create_profile(
        As2Id=local_as2, ProfileType='LOCAL',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )['ProfileId']
    ctx.on_cleanup(lambda _k=local_id: tf.delete_profile(ProfileId=_k))
    partner_as2 = ctx.unique_name('sim2real-behav-as2-')
    partner_id = tf.create_profile(
        As2Id=partner_as2, ProfileType='PARTNER',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )['ProfileId']
    ctx.on_cleanup(lambda _k=partner_id: tf.delete_profile(ProfileId=_k))

    def _by_id():
        tf = ctx.client('transfer')
        out = {}
        paginator = tf.get_paginator('list_profiles')
        for page in paginator.paginate():
            for p in page.get('Profiles', []):
                out[p['ProfileId']] = p
        return out
    _deadline = time.monotonic() + 30
    by_id = None
    while time.monotonic() < _deadline:
        by_id = _by_id()
        if local_id in by_id and partner_id in by_id:
            break
        time.sleep(2)
    else:
        raise AssertionError(
            'ListProfiles did not surface both created profiles within 30s: '
            f'local_id={local_id!r} partner_id={partner_id!r} present={sorted(by_id)!r}'
        )
    assert by_id[local_id]['ProfileType'] == 'LOCAL', (
        f"listed LOCAL profile {local_id} has ProfileType="
        f"{by_id[local_id]['ProfileType']!r}, expected 'LOCAL'"
    )
    assert by_id[local_id]['As2Id'] == local_as2, (
        f"listed LOCAL profile {local_id} has As2Id={by_id[local_id]['As2Id']!r}, "
        f"expected {local_as2!r}"
    )
    assert by_id[partner_id]['ProfileType'] == 'PARTNER', (
        f"listed PARTNER profile {partner_id} has ProfileType="
        f"{by_id[partner_id]['ProfileType']!r}, expected 'PARTNER'"
    )
    assert by_id[partner_id]['As2Id'] == partner_as2, (
        f"listed PARTNER profile {partner_id} has As2Id={by_id[partner_id]['As2Id']!r}, "
        f"expected {partner_as2!r}"
    )
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
