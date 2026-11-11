"""identity-policy-put-get-delete-roundtrip."""
from __future__ import annotations

import json

from behavioral_harness import tags


CHECK = "identity-policy-put-get-delete-roundtrip"
GROUP = 'identity'
SERVICES = ['ses']

def _unique_email(ctx, prefix="probe-"):
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}@example.com"


def _account_id(ctx):
    if not hasattr(ctx, "_ses_account_id"):
        ctx._ses_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._ses_account_id


def _identity_arn(ctx, identity):
    return f"arn:aws:ses:{ctx.region}:{_account_id(ctx)}:identity/{identity}"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutIdentityPolicy upserts a sending-authorization policy visible via Get/List, removed by Delete (idempotent)."""
    ses = ctx.client("ses")
    email = _unique_email(ctx)
    ses.verify_email_identity(EmailAddress=email)
    ctx.on_cleanup(lambda _n=email: ses.delete_identity(Identity=_n))

    account = _account_id(ctx)
    policy_name = ctx.unique_name("sim2real-behav-policy-")
    policy_doc = (
        '{"Version":"2008-10-17","Statement":[{"Sid":"probe","Effect":"Allow",'
        f'"Principal":{{"AWS":"arn:aws:iam::{account}:root"}},'
        f'"Action":"ses:SendEmail","Resource":"{_identity_arn(ctx, email)}"}}]}}'
    )
    ses.put_identity_policy(Identity=email, PolicyName=policy_name, Policy=policy_doc)

    names = ses.list_identity_policies(Identity=email)["PolicyNames"]
    assert policy_name in names, "policy missing from ListIdentityPolicies after PutIdentityPolicy"

    got = ses.get_identity_policies(Identity=email, PolicyNames=[policy_name])["Policies"]
    assert policy_name in got, "GetIdentityPolicies did not return the requested policy"
    stored = json.loads(got[policy_name])["Statement"][0]
    assert stored["Sid"] == "probe", f"stored policy Sid was not preserved: {stored}"
    assert stored["Action"] == "ses:SendEmail", f"stored policy Action was not preserved: {stored}"
    assert stored["Resource"] == _identity_arn(ctx, email), (
        f"stored policy Resource was not preserved: {stored}"
    )

    # Requesting a policy that does not exist returns an empty map, not an error.
    absent = ses.get_identity_policies(
        Identity=email, PolicyNames=[ctx.unique_name("sim2real-behav-absent-")]
    )["Policies"]
    assert absent == {}, f"expected empty Policies map for unknown policy name, got {absent}"

    ses.delete_identity_policy(Identity=email, PolicyName=policy_name)
    names_after = ses.list_identity_policies(Identity=email)["PolicyNames"]
    assert policy_name not in names_after, "policy still listed after DeleteIdentityPolicy"

    # Deleting a non-existent policy is idempotent, not an error.
    ses.delete_identity_policy(Identity=email, PolicyName=policy_name)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
