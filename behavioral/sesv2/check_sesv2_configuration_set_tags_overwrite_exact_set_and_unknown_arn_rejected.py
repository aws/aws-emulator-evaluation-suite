"""sesv2-configuration-set-tags-overwrite-exact-set-and-unknown-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sesv2-configuration-set-tags-overwrite-exact-set-and-unknown-arn-rejected"
GROUP = 'tagging-v2'
SERVICES = ['sesv2']


def _error(fn) -> tuple[str, str]:
    """The (code, message) ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Inline tags surface exactly through GetConfigurationSet and ListTagsForResource, and
    TagResource overwrites one key within that exact set. Both calls fail NotFoundException on an
    unknown set ARN, leaving the real set's tags unchanged.
    """
    ses = ctx.client('sesv2')
    account = ctx.account
    name = ctx.unique_name('sim2real-behav-v2cstag-')
    arn = f'arn:aws:ses:{ctx.region}:{account}:configuration-set/{name}'

    ses.create_configuration_set(
        ConfigurationSetName=name,
        Tags=[{'Key': 'env', 'Value': 'dev'}, {'Key': 'team', 'Value': 'core'}],
    )
    ctx.on_cleanup(lambda: ses.delete_configuration_set(ConfigurationSetName=name))

    get_tags = {t['Key']: t['Value'] for t in ses.get_configuration_set(ConfigurationSetName=name)['Tags']}
    assert get_tags == {'env': 'dev', 'team': 'core'}, (
        f"GetConfigurationSet Tags were {get_tags!r}, expected exactly env=dev, team=core"
    )
    list_tags = {t['Key']: t['Value'] for t in ses.list_tags_for_resource(ResourceArn=arn)['Tags']}
    assert list_tags == {'env': 'dev', 'team': 'core'}, (
        f"ListTagsForResource Tags were {list_tags!r}, expected exactly env=dev, team=core"
    )

    ses.tag_resource(ResourceArn=arn, Tags=[{'Key': 'env', 'Value': 'prod'}])
    overwritten = ses.list_tags_for_resource(ResourceArn=arn)['Tags']
    overwritten_map = {t['Key']: t['Value'] for t in overwritten}
    assert len(overwritten) == 2, f"expected exactly 2 tags after the overwrite, got {overwritten!r}"
    assert overwritten_map == {'env': 'prod', 'team': 'core'}, (
        f"tags after the overwrite were {overwritten_map!r}, expected exactly env=prod, team=core"
    )

    ghost_name = ctx.unique_name('sim2real-behav-v2cstag-missing-')
    ghost_arn = f'arn:aws:ses:{ctx.region}:{account}:configuration-set/{ghost_name}'
    expected_message = f'No ConfigurationSet present with name: {ghost_name}'

    code, message = _error(lambda: ses.tag_resource(ResourceArn=ghost_arn, Tags=[{'Key': 'k', 'Value': 'v'}]))
    assert code == 'NotFoundException', f"TagResource on an unknown set gave {code!r}, expected NotFoundException"
    assert message == expected_message, f"TagResource message was {message!r}, expected {expected_message!r}"

    code2, message2 = _error(lambda: ses.list_tags_for_resource(ResourceArn=ghost_arn))
    assert code2 == 'NotFoundException', (
        f"ListTagsForResource on an unknown set gave {code2!r}, expected NotFoundException"
    )
    assert message2 == expected_message, f"ListTagsForResource message was {message2!r}, expected {expected_message!r}"

    after_map = {t['Key']: t['Value'] for t in ses.list_tags_for_resource(ResourceArn=arn)['Tags']}
    assert after_map == {'env': 'prod', 'team': 'core'}, (
        f"the real set's tags changed to {after_map!r} after the refused calls, expected env=prod, team=core unchanged"
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
