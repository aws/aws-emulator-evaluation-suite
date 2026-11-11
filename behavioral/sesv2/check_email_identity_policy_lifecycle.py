"""email-identity-policy-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "email-identity-policy-lifecycle"
GROUP = 'identity'
SERVICES = ['sesv2']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """create policy -> list policies -> update -> list -> delete policy -> list policies (gone) -> mutation on the dead policy name is rejected."""
    ses = ctx.client('sesv2')
    email = ctx.unique_name('sim2real-behav-identity-policy-') + '@example.com'
    ses.create_email_identity(EmailIdentity=email, Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda _k=email: ses.delete_email_identity(EmailIdentity=_k))
    policy_name = ctx.unique_name('sim2real-behav-Policy')
    identity_arn = f"arn:aws:ses:{ctx.region}:{ctx.client('sts').get_caller_identity()['Account']}:identity/{email}"
    policy_doc = '{"Version":"2012-10-17","Statement":[{"Sid":"stmt1","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::' + ctx.client('sts').get_caller_identity()['Account'] + ':root"},"Action":["ses:SendEmail","ses:SendRawEmail"],"Resource":"' + identity_arn + '"}]}'
    ses.create_email_identity_policy(EmailIdentity=email, PolicyName=policy_name, Policy=policy_doc)
    ctx.on_cleanup(lambda _k=(email, policy_name): _ignore_not_found(lambda: ses.delete_email_identity_policy(EmailIdentity=_k[0], PolicyName=_k[1])))
    policies = ses.get_email_identity_policies(EmailIdentity=email)
    assert policy_name in policies['Policies'], f"expected {policy_name!r} in GetEmailIdentityPolicies after create, got {policies['Policies']}"
    updated_doc = policy_doc.replace('"stmt1"', '"stmt2"')
    ses.update_email_identity_policy(EmailIdentity=email, PolicyName=policy_name, Policy=updated_doc)
    policies_updated = ses.get_email_identity_policies(EmailIdentity=email)
    assert 'stmt2' in policies_updated['Policies'][policy_name], f"expected updated policy body containing 'stmt2', got {policies_updated['Policies'][policy_name]!r}"
    ses.delete_email_identity_policy(EmailIdentity=email, PolicyName=policy_name)
    policies_after = ses.get_email_identity_policies(EmailIdentity=email)
    assert policy_name not in policies_after['Policies'], f"expected {policy_name!r} absent from GetEmailIdentityPolicies after delete, got {policies_after['Policies']}"
    dead = _error(lambda: ses.update_email_identity_policy(EmailIdentity=email, PolicyName=policy_name, Policy=updated_doc))
    assert dead.get('Code') == 'NotFoundException', f"expected NotFoundException updating the deleted policy {policy_name!r}, got {dead!r}"
    expected = f'Policy <{policy_name}> does not exist'
    assert dead.get('Message') == expected, f"expected message {expected!r}, got {dead.get('Message')!r}"


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _ignore_not_found(fn):
    """Teardown helper: a resource the check already deleted reads as not-found."""
    try:
        fn()
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
