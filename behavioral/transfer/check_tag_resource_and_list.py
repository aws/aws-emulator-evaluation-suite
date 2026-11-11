"""tag-resource-and-list."""
from __future__ import annotations

from behavioral_harness import tags
CHECK = "tag-resource-and-list"
GROUP = 'tags'
SERVICES = ['transfer']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource on a profile ARN is visible via ListTagsForResource."""
    tf = ctx.client('transfer')
    _as2 = None or ctx.unique_name('sim2real-behav-as2-')
    pid = tf.create_profile(As2Id=_as2, ProfileType='LOCAL')['ProfileId']
    ctx.on_cleanup(lambda _k=pid: tf.delete_profile(ProfileId=_k))
    arn = tf.describe_profile(ProfileId=pid)['Profile']['Arn']
    tf.tag_resource(Arn=arn, Tags=[{'Key': 'Owner', 'Value': 'behav'}])
    resp = tf.list_tags_for_resource(Arn=arn)
    tags = resp['Tags']
    matching = [t for t in tags if t['Key'] == 'Owner']
    assert matching, f'tag Owner not found in {tags}'
    assert matching[0]['Value'] == 'behav', f"expected Owner='behav', got {matching[0]['Value']!r}"
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
