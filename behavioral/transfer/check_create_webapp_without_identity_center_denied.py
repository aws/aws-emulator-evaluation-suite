"""create-webapp-without-identity-center-denied."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "create-webapp-without-identity-center-denied"
GROUP = 'overly-permissive'
SERVICES = ['transfer']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateWebApp without sso:CreateApplication permission fails AccessDeniedException with the
    exact message naming that action, and creates no web app."""
    tf = ctx.client('transfer')
    caller = ctx.client('sts').get_caller_identity()
    account = caller['Account']
    caller_arn = caller['Arn']

    before = _web_app_ids(tf)
    marker = ctx.unique_name('sim2real-behav-webapp-')

    try:
        created = tf.create_web_app(IdentityProviderDetails={'IdentityCenterConfig': {'InstanceArn': 'arn:aws:sso:::instance/ssoins-0000000000000000', 'Role': f'arn:aws:iam::{account}:role/does-not-exist'}}, Tags=[{'Key': 'Name', 'Value': marker}])
    except ClientError as _e:
        code = _e.response.get('Error', {}).get('Code')
        message = _e.response.get('Error', {}).get('Message', '')
    else:
        raise AssertionError(f'expected CreateWebApp to be denied, but it succeeded and returned {created!r}')
    assert code == 'AccessDeniedException', f'expected AccessDeniedException for the sso:CreateApplication boundary, got {code}'
    assert message == (
        f'User: {caller_arn} is not authorized to perform: sso:CreateApplication on resource: '
        'arn:aws:sso::*:application/ssoins-0000000000000000/* because no resource-based policy '
        'allows the sso:CreateApplication action'
    ), f'unexpected sso:CreateApplication denial message: {message!r}'

    created_ids = _tagged_web_apps(tf, _web_app_ids(tf) - before, 'Name', marker)
    assert created_ids == [], f'expected no web app created despite the denial, got {created_ids}'


def _web_app_ids(tf):
    """Every listed web app id, across all pages."""
    ids = set()
    kwargs = {}
    while True:
        resp = tf.list_web_apps(**kwargs)
        ids.update(w['WebAppId'] for w in resp.get('WebApps', []))
        if not resp.get('NextToken'):
            return ids
        kwargs = {'NextToken': resp['NextToken']}


def _tagged_web_apps(tf, ids, key, value):
    """The web apps among ids tagged key=value; one already deleted is not this check's."""
    own = []
    for web_app_id in sorted(ids):
        try:
            web_app = tf.describe_web_app(WebAppId=web_app_id)['WebApp']
        except ClientError as exc:
            if exc.response['Error']['Code'] == 'ResourceNotFoundException':
                continue
            raise
        if {'Key': key, 'Value': value} in web_app.get('Tags', []):
            own.append(web_app_id)
    return own


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
