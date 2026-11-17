"""sesv2-email-template-tag-lifecycle-through-delete."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "sesv2-email-template-tag-lifecycle-through-delete"
GROUP = 'tagging-v2'
SERVICES = ['sesv2']


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response['Error']['Code'] in not_found:
                return
            raise
    return run_undo


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError('expected the call to raise a ClientError, but it succeeded')


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SESv2 tags on an email template track CreateEmailTemplate, TagResource and UntagResource
    exactly, and ListTagsForResource on the ARN raises NotFoundException once the template is deleted.
    """
    ses = ctx.client('sesv2')
    name = ctx.unique_name('sim2real-behav-tpltaglc-')
    arn = f'arn:aws:ses:{ctx.region}:{ctx.account}:template/{name}'

    ses.create_email_template(
        TemplateName=name,
        TemplateContent={'Subject': 'S', 'Text': 'T'},
        Tags=[{'Key': 'env', 'Value': 'dev'}, {'Key': 'team', 'Value': 'core'}],
    )
    ctx.on_cleanup(_teardown(lambda: ses.delete_email_template(TemplateName=name), 'NotFoundException'))

    after_create = {t['Key']: t['Value'] for t in ses.list_tags_for_resource(ResourceArn=arn)['Tags']}
    assert after_create == {'env': 'dev', 'team': 'core'}, (
        f'expected inline tags {{"env": "dev", "team": "core"}} after create, got {after_create!r}'
    )

    ses.tag_resource(ResourceArn=arn, Tags=[{'Key': 'owner', 'Value': 'alice'}])
    after_tag = {t['Key']: t['Value'] for t in ses.list_tags_for_resource(ResourceArn=arn)['Tags']}
    assert after_tag == {'env': 'dev', 'team': 'core', 'owner': 'alice'}, (
        f'expected env+team+owner after TagResource, got {after_tag!r}'
    )

    ses.untag_resource(ResourceArn=arn, TagKeys=['env'])
    after_untag = {t['Key']: t['Value'] for t in ses.list_tags_for_resource(ResourceArn=arn)['Tags']}
    assert after_untag == {'team': 'core', 'owner': 'alice'}, (
        f'expected only team+owner after UntagResource(env), got {after_untag!r}'
    )

    ses.delete_email_template(TemplateName=name)
    code, msg = _error(lambda: ses.list_tags_for_resource(ResourceArn=arn))
    assert code == 'NotFoundException', f'expected NotFoundException reading tags after delete, got {code!r}'
    expected_msg = f'No Template present with name: {name}'
    assert msg == expected_msg, f'expected message {expected_msg!r}, got {msg!r}'


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
