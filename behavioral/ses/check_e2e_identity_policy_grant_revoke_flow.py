"""e2e-identity-policy-grant-revoke-flow."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "e2e-identity-policy-grant-revoke-flow"
GROUP = "e2e"
SERVICES = ["ses"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A sending-authorization policy put on a pending-verification identity is listed and readable;
    deleting it removes it from both ListIdentityPolicies and GetIdentityPolicies."""
    ses = ctx.client("ses")
    identity = f"{ctx.unique_name('sim2real-ses-id')}@example.com"
    ses.verify_email_identity(EmailAddress=identity)
    ctx.on_cleanup(lambda: ses.delete_identity(Identity=identity))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy_name = ctx.unique_name("sim2real-ses-pol-")
    policy_doc = {
        "Version": "2008-10-17",
        "Statement": [
            {
                "Sid": "AllowDelegateSend",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "ses:SendEmail",
                "Resource": f"arn:aws:ses:{ctx.region}:{account_id}:identity/{identity}",
            }
        ],
    }
    ses.put_identity_policy(
        Identity=identity, PolicyName=policy_name, Policy=json.dumps(policy_doc)
    )

    names = ses.list_identity_policies(Identity=identity)["PolicyNames"]
    assert policy_name in names, (
        f"expected {policy_name!r} in ListIdentityPolicies after PutIdentityPolicy, got {names!r}"
    )

    fetched = ses.get_identity_policies(Identity=identity, PolicyNames=[policy_name])[
        "Policies"
    ]
    assert policy_name in fetched, (
        f"expected {policy_name!r} in GetIdentityPolicies Policies, got keys {list(fetched)!r}"
    )
    parsed = json.loads(fetched[policy_name])
    assert parsed["Statement"][0]["Action"] == "ses:SendEmail", (
        f"expected stored policy Action 'ses:SendEmail', got {parsed['Statement'][0].get('Action')!r}"
    )
    assert parsed["Statement"][0]["Sid"] == "AllowDelegateSend", (
        f"expected stored policy Sid 'AllowDelegateSend', got {parsed['Statement'][0].get('Sid')!r}"
    )

    ses.delete_identity_policy(Identity=identity, PolicyName=policy_name)

    names_after = ses.list_identity_policies(Identity=identity)["PolicyNames"]
    assert policy_name not in names_after, (
        f"expected {policy_name!r} absent from ListIdentityPolicies after DeleteIdentityPolicy, "
        f"still present in {names_after!r}"
    )

    fetched_after = ses.get_identity_policies(
        Identity=identity, PolicyNames=[policy_name]
    )["Policies"]
    assert policy_name not in fetched_after, (
        f"expected {policy_name!r} absent from GetIdentityPolicies after DeleteIdentityPolicy, "
        f"still present in {fetched_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
