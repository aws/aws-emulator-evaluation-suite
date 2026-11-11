"""untag-resource-removes-key."""
from __future__ import annotations

from behavioral_harness import tags
CHECK = "untag-resource-removes-key"
GROUP = 'tags'
SERVICES = ['transfer']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the listed key, leaving other tags intact."""
    tf = ctx.client('transfer')
    _as2 = None or ctx.unique_name('sim2real-behav-as2-')
    pid = tf.create_profile(As2Id=_as2, ProfileType='LOCAL')['ProfileId']
    ctx.on_cleanup(lambda _k=pid: tf.delete_profile(ProfileId=_k))
    arn = tf.describe_profile(ProfileId=pid)['Profile']['Arn']
    tf.tag_resource(Arn=arn, Tags=[{'Key': 'Owner', 'Value': 'behav'}, {'Key': 'Team', 'Value': 'sim2real'}])
    tags_before = {t['Key']: t['Value'] for t in tf.list_tags_for_resource(Arn=arn)['Tags']}
    assert tags_before == {'Owner': 'behav', 'Team': 'sim2real'}, f'expected both tags present before untag: {tags_before}'
    tf.untag_resource(Arn=arn, TagKeys=['Owner'])
    tags_after = {t['Key']: t['Value'] for t in tf.list_tags_for_resource(Arn=arn)['Tags']}
    assert tags_after == {'Team': 'sim2real'}, f'expected only Team tag to remain, got {tags_after}'
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
