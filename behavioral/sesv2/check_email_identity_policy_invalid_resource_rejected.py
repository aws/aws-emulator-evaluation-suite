"""email-identity-policy-invalid-resource-rejected."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "email-identity-policy-invalid-resource-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sesv2']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An identity policy whose Resource is not an ARN MUST be rejected, and no policy is created."""
    ses = ctx.client('sesv2')
    email = ctx.unique_name('sim2real-behav-identity-badpolicy-') + '@example.com'
    ses.create_email_identity(EmailIdentity=email)
    ctx.on_cleanup(lambda _k=email: ses.delete_email_identity(EmailIdentity=_k))
    account = ctx.client('sts').get_caller_identity()['Account']
    identity_arn = f"arn:aws:ses:{ctx.region}:{account}:identity/{email}"

    good_name = ctx.unique_name('sim2real-behav-GoodPolicy')
    good_doc = '{"Version":"2012-10-17","Statement":[{"Sid":"stmt1","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::' + account + ':root"},"Action":["ses:SendEmail"],"Resource":"' + identity_arn + '"}]}'
    ses.create_email_identity_policy(EmailIdentity=email, PolicyName=good_name, Policy=good_doc)
    ctx.on_cleanup(lambda _k=(email, good_name): ses.delete_email_identity_policy(EmailIdentity=_k[0], PolicyName=_k[1]))
    policies = ses.get_email_identity_policies(EmailIdentity=email)
    assert good_name in policies['Policies'], f'positive control failed: {policies["Policies"]}'

    bad_name = ctx.unique_name('sim2real-behav-BadPolicy')
    bad_doc = '{"Version":"2012-10-17","Statement":[{"Sid":"stmt1","Effect":"Allow","Principal":{"AWS":"*"},"Action":["ses:SendEmail"],"Resource":"*"}]}'
    err = _error(lambda: ses.create_email_identity_policy(EmailIdentity=email, PolicyName=bad_name, Policy=bad_doc))
    assert err.get('Code') == 'BadRequestException', f'expected BadRequestException, got {err!r}'
    expected = "Invalid ARN: ARNs must start with 'arn:': *"
    assert err.get('Message') == expected, f"expected message {expected!r}, got {err.get('Message')!r}"

    policies_after = ses.get_email_identity_policies(EmailIdentity=email)
    assert bad_name not in policies_after['Policies'], f'bad policy was created despite rejection: {policies_after["Policies"]}'
    assert good_name in policies_after['Policies'], f'positive control policy vanished after rejection: {policies_after["Policies"]}'


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
