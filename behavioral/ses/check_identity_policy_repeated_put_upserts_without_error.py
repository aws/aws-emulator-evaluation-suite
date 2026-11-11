"""identity-policy-repeated-put-upserts-without-error."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "identity-policy-repeated-put-upserts-without-error"
GROUP = "identity"
SERVICES = ["ses"]


def _account_id(ctx):
    if not hasattr(ctx, "_ses_account_id"):
        ctx._ses_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._ses_account_id


def _identity_arn(ctx, identity):
    return f"arn:aws:ses:{ctx.region}:{_account_id(ctx)}:identity/{identity}"


def _policy_doc(account, resource_arn, sid):
    return (
        '{"Version":"2008-10-17","Statement":[{"Sid":"' + sid + '","Effect":"Allow",'
        f'"Principal":{{"AWS":"arn:aws:iam::{account}:root"}},'
        f'"Action":"ses:SendEmail","Resource":"{resource_arn}"}}]}}'
    )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutIdentityPolicy is an upsert: a second call with the same PolicyName succeeds and REPLACES
    the stored document (not merges or appends it), and ListIdentityPolicies lists the name once.
    """
    ses = ctx.client("ses")
    account = _account_id(ctx)
    identity = ctx.unique_name("sim2real-behav-idpolupsert-") + "@example.com"
    ses.verify_email_identity(EmailAddress=identity)
    ctx.on_cleanup(lambda: ses.delete_identity(Identity=identity))

    arn = _identity_arn(ctx, identity)
    policy_name = ctx.unique_name("sim2real-behav-policy-")

    first_doc = _policy_doc(account, arn, "first")
    ses.put_identity_policy(Identity=identity, PolicyName=policy_name, Policy=first_doc)
    ctx.on_cleanup(lambda: ses.delete_identity_policy(Identity=identity, PolicyName=policy_name))

    got_first = ses.get_identity_policies(Identity=identity, PolicyNames=[policy_name])["Policies"]
    assert json.loads(got_first[policy_name])["Statement"][0]["Sid"] == "first", (
        f"expected the first PutIdentityPolicy to store Sid 'first', got {got_first}"
    )

    second_doc = _policy_doc(account, arn, "second")
    # Must not raise: a repeated put is not a duplicate error.
    ses.put_identity_policy(Identity=identity, PolicyName=policy_name, Policy=second_doc)

    got_second = ses.get_identity_policies(Identity=identity, PolicyNames=[policy_name])["Policies"]
    assert policy_name in got_second, (
        f"expected {policy_name!r} still present after the repeated put, got keys "
        f"{sorted(got_second)}"
    )
    stored = json.loads(got_second[policy_name])
    assert stored["Statement"][0]["Sid"] == "second", (
        f"expected the second PutIdentityPolicy to REPLACE the stored document (Sid 'second'), "
        f"got {stored}"
    )
    assert len(stored["Statement"]) == 1, (
        f"expected the second put to replace rather than append to the statement list, "
        f"got {len(stored['Statement'])} statements: {stored}"
    )

    names = ses.list_identity_policies(Identity=identity)["PolicyNames"]
    assert names.count(policy_name) == 1, (
        f"expected {policy_name!r} to appear exactly once in ListIdentityPolicies after two "
        f"puts under the same name, got {names!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
