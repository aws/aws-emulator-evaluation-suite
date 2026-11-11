"""tag-resource-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
CHECK = "tag-resource-lifecycle"
GROUP = 'tags'
SERVICES = ['sesv2']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource -> ListTagsForResource(reflects) -> UntagResource -> reflects removal."""
    ses = ctx.client('sesv2')
    name = ctx.unique_name('sim2real-behav-cfgset-tags-')
    ses.create_configuration_set(ConfigurationSetName=name)
    ctx.on_cleanup(lambda _k=name: ses.delete_configuration_set(ConfigurationSetName=_k))
    resource_arn = f"arn:aws:ses:{ctx.region}:{ctx.client('sts').get_caller_identity()['Account']}:configuration-set/{name}"
    ses.tag_resource(ResourceArn=resource_arn, Tags=[{'Key': 'env', 'Value': 'test'}, {'Key': 'owner', 'Value': 'keep'}])
    ctx.on_cleanup(lambda _k=(resource_arn, ['env', 'owner']): ses.untag_resource(ResourceArn=_k[0], TagKeys=_k[1]))
    tags = ses.list_tags_for_resource(ResourceArn=resource_arn)
    tag_map = {t['Key']: t['Value'] for t in tags['Tags']}
    assert tag_map.get('env') == 'test' and tag_map.get('owner') == 'keep', tag_map
    ses.untag_resource(ResourceArn=resource_arn, TagKeys=['env'])
    tags_after = ses.list_tags_for_resource(ResourceArn=resource_arn)
    tag_map_after = {t['Key']: t['Value'] for t in tags_after['Tags']}
    assert 'env' not in tag_map_after and tag_map_after.get('owner') == 'keep', tag_map_after
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
