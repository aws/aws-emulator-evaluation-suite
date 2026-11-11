"""set-identity-pool-roles-invalid-role-arn-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-identity-pool-roles-invalid-role-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetIdentityPoolRoles with a Roles value that is not an IAM role ARN is refused with
    NotAuthorizedException and the exact message and stores nothing, while a real role ARN for the
    same key is stored."""
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    pool = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=False,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    # Baseline: no roles configured yet.
    baseline = ci.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert not baseline.get("Roles"), f"expected no roles configured yet, got {baseline.get('Roles')!r}"

    garbage_arn = "not-a-real-arn-just-a-long-garbage-string-1234567890"

    def _set_garbage_role():
        ci.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"authenticated": garbage_arn})

    code, message = _error(_set_garbage_role)
    assert code == "NotAuthorizedException", f"expected NotAuthorizedException, got {code!r}"
    expected = f"Access to Role '{garbage_arn}' is forbidden."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the malformed role config did not persist.
    after_broken = ci.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert not after_broken.get("Roles"), (
        f"the rejected malformed Roles value was nonetheless persisted: {after_broken.get('Roles')!r}"
    )

    # Positive control: a real IAM role ARN for the same key is accepted.
    role_name = ctx.unique_name("sim2real-behav-role-")

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "authenticated"},
                },
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    ci.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"authenticated": role_arn})
    after_valid = ci.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert after_valid["Roles"]["authenticated"] == role_arn, (
        f"expected the restored valid role ARN {role_arn!r} to persist, got "
        f"{after_valid['Roles'].get('authenticated')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
