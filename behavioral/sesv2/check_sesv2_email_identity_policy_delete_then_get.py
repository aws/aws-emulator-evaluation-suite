"""sesv2-email-identity-policy-delete-then-get."""
from __future__ import annotations
import json

from behavioral_harness import tags

CHECK = "sesv2-email-identity-policy-delete-then-get"
GROUP = 'identity-policy-v2'
SERVICES = ['sesv2']


def _v2_policy_identity(ctx) -> str:
    ses = ctx.client('sesv2')
    domain = ctx.unique_name('sim2real-behav-v2pol-') + '.example.com'
    ses.create_email_identity(EmailIdentity=domain, Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda _k=domain: ses.delete_email_identity(EmailIdentity=_k))
    return domain


def _v2_valid_policy_doc(ctx, identity: str, sid: str = 'stmt1') -> str:
    """A parseable SES sending-authorization policy for ``identity``; SES rejects an
    empty-Statement document with ``BadRequestException: Unable to parse policy``."""
    account = ctx.client('sts').get_caller_identity()['Account']
    return json.dumps({
        'Version': '2012-10-17',
        'Statement': [{
            'Sid': sid,
            'Effect': 'Allow',
            'Principal': {'AWS': f"arn:aws:iam::{account}:root"},
            'Action': ['ses:SendEmail', 'ses:SendRawEmail'],
            'Resource': f"arn:aws:ses:{ctx.region}:{account}:identity/{identity}",
        }],
    })


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SESv2 DeleteEmailIdentityPolicy removes exactly the named policy: GetEmailIdentityPolicies
    stops reporting it afterward, while a sibling policy on the same identity survives untouched.
    """
    ses = ctx.client('sesv2')
    identity = _v2_policy_identity(ctx)

    ses.create_email_identity_policy(EmailIdentity=identity, PolicyName='keep', Policy=_v2_valid_policy_doc(ctx, identity, 'stmtKeep'))
    ctx.on_cleanup(lambda _k=identity: ses.delete_email_identity_policy(EmailIdentity=_k, PolicyName='keep'))

    ses.create_email_identity_policy(EmailIdentity=identity, PolicyName='p2', Policy=_v2_valid_policy_doc(ctx, identity, 'stmt2'))
    before = ses.get_email_identity_policies(EmailIdentity=identity)['Policies']
    assert 'p2' in before, f"policy p2 missing from GetEmailIdentityPolicies right after creation: {before!r}"
    assert 'keep' in before, f"sibling policy 'keep' missing before delete even runs: {before!r}"

    ses.delete_email_identity_policy(EmailIdentity=identity, PolicyName='p2')

    after = ses.get_email_identity_policies(EmailIdentity=identity)['Policies']
    assert 'p2' not in after, f"DeleteEmailIdentityPolicy ran, but 'p2' is still reported: {after!r}"
    assert 'keep' in after, f"deleting 'p2' collaterally removed the sibling policy 'keep': {after!r}"
    assert '"Sid":"stmtKeep"' in after['keep'].replace(' ', ''), (
        f"sibling policy 'keep' survived by name but its body changed: {after['keep']!r}"
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
