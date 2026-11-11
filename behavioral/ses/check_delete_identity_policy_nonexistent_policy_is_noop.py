"""delete-identity-policy-nonexistent-policy-is-noop."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-identity-policy-nonexistent-policy-is-noop"
GROUP = "error-semantics"
SERVICES = ["ses"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteIdentityPolicy for a never-created PolicyName succeeds as a no-op, and
    GetIdentityPolicies returns the identity's real policy but not the never-created one."""
    ses = ctx.client("ses")
    identity = f"{ctx.unique_name('sim2real-ses-idpolicy-')}@example.com"
    ses.verify_email_identity(EmailAddress=identity)
    ctx.on_cleanup(lambda: ses.delete_identity(Identity=identity))

    account = ctx.client("sts").get_caller_identity()["Account"]
    real_policy = ctx.unique_name("sim2real-ses-realpolicy-")
    ses.put_identity_policy(
        Identity=identity,
        PolicyName=real_policy,
        Policy=(
            '{"Version":"2008-10-17","Statement":[{"Sid":"probe","Effect":"Allow",'
            f'"Principal":{{"AWS":"arn:aws:iam::{account}:root"}},'
            f'"Action":"ses:SendEmail","Resource":"arn:aws:ses:{ctx.region}:{account}:identity/{identity}"}}]}}'
        ),
    )

    never_created_policy = ctx.unique_name("sim2real-ses-neverpolicy-")

    # Must not raise — this is the assertion under test.
    ses.delete_identity_policy(Identity=identity, PolicyName=never_created_policy)

    policies = ses.get_identity_policies(
        Identity=identity, PolicyNames=[real_policy, never_created_policy]
    )["Policies"]
    assert real_policy in policies, (
        f"positive control failed: GetIdentityPolicies dropped a policy it actually holds, "
        f"got keys {sorted(policies)}"
    )
    assert never_created_policy not in policies, (
        f"GetIdentityPolicies unexpectedly returned a policy body for a name never created, "
        f"got keys {sorted(policies)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
