"""identity-id-format-stable-across-calls."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-id-format-stable-across-calls"
GROUP = "representation"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The IdentityId returned by GetId is byte-identical across DescribeIdentity and
    GetCredentialsForIdentity, with no format drift (e.g. case-folding, trimming, re-encoding)."""
    ci = ctx.client("cognito-identity")

    pool = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    role_arn, role_name = _create_cognito_role(ctx, pool_id, authenticated=False)
    ci.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"unauthenticated": role_arn})

    got = ci.get_id(IdentityPoolId=pool_id)
    identity_id = got["IdentityId"]

    described = ci.describe_identity(IdentityId=identity_id)
    assert described["IdentityId"] == identity_id, (
        f"DescribeIdentity returned a differently-formatted IdentityId: {described['IdentityId']!r} "
        f"vs GetId's {identity_id!r}"
    )

    creds_resp = _retry_get_credentials(ctx, identity_id)
    assert creds_resp["IdentityId"] == identity_id, (
        f"GetCredentialsForIdentity returned a differently-formatted IdentityId: "
        f"{creds_resp['IdentityId']!r} vs GetId's {identity_id!r}"
    )


def _create_cognito_role(ctx, pool_id, authenticated, extra_conditions=None, inline_policy=None):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    amr = "authenticated" if authenticated else "unauthenticated"
    string_equals = {"cognito-identity.amazonaws.com:aud": pool_id}
    if extra_conditions:
        string_equals.update(extra_conditions)
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": ["sts:AssumeRoleWithWebIdentity", "sts:TagSession"],
                "Condition": {
                    "StringEquals": string_equals,
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": amr},
                },
            }
        ],
    }
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    if inline_policy:
        iam.put_role_policy(RoleName=name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(inline_policy))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-inline"))
    return role_arn, name


def _retry_get_credentials(ctx, identity_id, logins=None, timeout_s=90.0, interval_s=5.0):
    """IAM role/trust-policy propagation is eventually consistent; poll GetCredentialsForIdentity
    until the freshly-created role becomes assumable."""
    ci = ctx.client("cognito-identity")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            kwargs = {"IdentityId": identity_id}
            if logins:
                kwargs["Logins"] = logins
            return ci.get_credentials_for_identity(**kwargs)
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"GetCredentialsForIdentity never succeeded within {timeout_s}s: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
