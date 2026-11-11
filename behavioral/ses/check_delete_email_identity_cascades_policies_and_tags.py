"""delete-email-identity-cascades-policies-and-tags."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "delete-email-identity-cascades-policies-and-tags"
GROUP = 'identity-v2'
SERVICES = ['ses']

from botocore.exceptions import ClientError

_POLICY_NAME = 'sim2realCascadePolicy'


def _client_error(fn) -> ClientError:
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError('expected the call to be refused, but it succeeded')


def _delete_identity_if_present(fn, **kwargs) -> None:
    """Cleanup that tolerates the check having already deleted the identity, and nothing else."""
    try:
        fn(**kwargs)
    except ClientError as exc:
        if exc.response['Error']['Code'] not in ('NotFoundException', 'NotFound'):
            raise


def _identity_arn(region, account, identity) -> str:
    return f"arn:aws:ses:{region}:{account}:identity/{identity}"


def _policy_doc(account, identity_arn) -> str:
    return json.dumps({
        'Version': '2012-10-17',
        'Statement': [{
            'Sid': 'sim2realCascade',
            'Effect': 'Allow',
            'Principal': {'AWS': f"arn:aws:iam::{account}:root"},
            'Action': ['ses:SendEmail', 'ses:SendRawEmail'],
            'Resource': identity_arn,
        }],
    })


def _unique_domain(ctx, prefix='cascade-') -> str:
    # RFC 2606 reserved domain only.
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}.example.com"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting an email identity removes its policies and tags (a sibling keeps its own), and
    recreating the same name does not resurrect them.
    """
    v2 = ctx.client('sesv2')
    v1 = ctx.client('ses')
    account = ctx.client('sts').get_caller_identity()['Account']

    subject = _unique_domain(ctx, 'cascade-')
    sibling = _unique_domain(ctx, 'cascadectl-')
    subject_arn = _identity_arn(ctx.region, account, subject)
    sibling_arn = _identity_arn(ctx.region, account, sibling)

    for ident in (subject, sibling):
        v2.create_email_identity(EmailIdentity=ident, Tags=[{'Key': 'sim2real-role', 'Value': 'cascade'}])
        ctx.on_cleanup(lambda _i=ident: _delete_identity_if_present(
            v2.delete_email_identity, EmailIdentity=_i))
    for ident, arn in ((subject, subject_arn), (sibling, sibling_arn)):
        v2.create_email_identity_policy(
            EmailIdentity=ident, PolicyName=_POLICY_NAME, Policy=_policy_doc(account, arn))

    subject_policies = v2.get_email_identity_policies(EmailIdentity=subject)['Policies']
    assert _POLICY_NAME in subject_policies, (
        f"setup precondition: policy not attached to {subject!r}, got {sorted(subject_policies)}"
    )
    subject_tags = {t['Key'] for t in v2.list_tags_for_resource(ResourceArn=subject_arn)['Tags']}
    assert 'sim2real-role' in subject_tags, f"setup precondition: tag not attached, got {subject_tags!r}"
    v1_names = v1.list_identity_policies(Identity=subject)['PolicyNames']
    assert _POLICY_NAME in v1_names, (
        f"setup precondition: v1 must see the v2-created policy on one shared store, got {v1_names!r}"
    )

    v2.delete_email_identity(EmailIdentity=subject)

    err_pol = _client_error(lambda: v2.get_email_identity_policies(EmailIdentity=subject))
    assert (err_pol.response['Error']['Code'], err_pol.response['Error'].get('Message')) == (
        'NotFoundException',
        f"Email identity <{subject}> does not exist.",
    ), (
        f"reading policies of a deleted identity must be NotFoundException, got {err_pol.response['Error']!r}"
    )
    err_tags = _client_error(lambda: v2.list_tags_for_resource(ResourceArn=subject_arn))
    assert (err_tags.response['Error']['Code'], err_tags.response['Error'].get('Message')) == (
        'NotFoundException',
        f"No EmailIdentity present with name: {subject}",
    ), (
        f"reading tags of a deleted identity's ARN must be NotFoundException, got "
        f"{err_tags.response['Error']!r}"
    )
    # v1 ListIdentityPolicies declares no not-found error, so a deleted identity lists empty.
    v1_after = v1.list_identity_policies(Identity=subject)['PolicyNames']
    assert v1_after == [], (
        f"v1 must report no policies for a deleted identity, got {v1_after!r}"
    )

    # Control: the delete is scoped to one identity.
    sib_policies = v2.get_email_identity_policies(EmailIdentity=sibling)['Policies']
    assert _POLICY_NAME in sib_policies, (
        f"deleting one identity must not remove a sibling's policies, got {sorted(sib_policies)}"
    )
    sib_tags = {t['Key'] for t in v2.list_tags_for_resource(ResourceArn=sibling_arn)['Tags']}
    assert 'sim2real-role' in sib_tags, (
        f"deleting one identity must not remove a sibling's tags, got {sib_tags!r}"
    )

    v2.create_email_identity(EmailIdentity=subject)
    reborn_policies = v2.get_email_identity_policies(EmailIdentity=subject)['Policies']
    assert reborn_policies == {}, (
        'recreating an identity must not resurrect the deleted identity\'s authorization policies; got '
        f"{reborn_policies!r}"
    )
    reborn_tags = v2.list_tags_for_resource(ResourceArn=subject_arn)['Tags']
    assert reborn_tags == [], (
        f"recreating an identity must not resurrect its tags; got {reborn_tags!r}"
    )
    reborn_v1 = v1.list_identity_policies(Identity=subject)['PolicyNames']
    assert reborn_v1 == [], f"v1 must agree the recreated identity has no policies, got {reborn_v1!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
