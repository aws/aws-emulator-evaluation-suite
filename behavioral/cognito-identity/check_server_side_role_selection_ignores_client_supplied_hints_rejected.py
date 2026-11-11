"""server-side-role-selection-ignores-client-supplied-hints-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "server-side-role-selection-ignores-client-supplied-hints-rejected"
GROUP = "server-side"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCredentialsForIdentity rejects a CustomRoleArn not attached to the pool with
    InvalidParameterException, even when that role trusts the pool; the configured role
    still works before and after."""
    cid = ctx.client("cognito-identity")
    pool = cid.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: cid.delete_identity_pool(IdentityPoolId=pool_id))

    role_a_name, role_a_arn = _create_trusting_role(ctx, pool_id, "unauthenticated")
    # role_b independently trusts this same pool (so a rejection cannot be blamed on its trust
    # policy) but is never attached via SetIdentityPoolRoles/RoleMappings.
    _role_b_name, role_b_arn = _create_trusting_role(ctx, pool_id, "unauthenticated")
    cid.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"unauthenticated": role_a_arn})

    identity_id = cid.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: cid.delete_identities(IdentityIdsToDelete=[identity_id]))

    creds = _get_credentials_with_retry(ctx, identity_id)["Credentials"]
    arn = _assumed_role_arn(ctx, creds)
    assert f"assumed-role/{role_a_name}/" in arn, f"expected role A by default, got {arn}"

    code, message = _error(
        lambda: cid.get_credentials_for_identity(IdentityId=identity_id, CustomRoleArn=role_b_arn)
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == (
        "Only SAML providers and providers with RoleMappings support custom role ARN."
    ), (
        f"expected the exact refusal message AWS returns, got {message!r}"
    )

    creds_again = _get_credentials_with_retry(ctx, identity_id, timeout_s=15.0)["Credentials"]
    arn_again = _assumed_role_arn(ctx, creds_again)
    assert f"assumed-role/{role_a_name}/" in arn_again, (
        f"role selection changed after the rejected hint: {arn_again}"
    )


def _create_trusting_role(ctx, pool_id: str, amr: str, max_session_duration: int = 3600):
    import json

    iam = ctx.client("iam")
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
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": amr},
                },
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        MaxSessionDuration=max_session_duration,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_name, role["Arn"]


def _get_credentials_with_retry(
    ctx, identity_id, logins=None, custom_role_arn=None, timeout_s=45.0, interval_s=3.0
):
    import time

    from botocore.exceptions import ClientError

    cid = ctx.client("cognito-identity")
    kwargs = {"IdentityId": identity_id}
    if logins:
        kwargs["Logins"] = logins
    if custom_role_arn:
        kwargs["CustomRoleArn"] = custom_role_arn
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return cid.get_credentials_for_identity(**kwargs)
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"GetCredentialsForIdentity never succeeded within {timeout_s}s: {last_exc}")


def _assumed_role_arn(ctx, credentials):
    """The caller ARN of the vended temporary credentials, read through the target's STS."""
    return ctx.client(
        "sts",
        creds={
            "aws_access_key_id": credentials["AccessKeyId"],
            "aws_secret_access_key": credentials["SecretKey"],
            "aws_session_token": credentials["SessionToken"],
        },
    ).get_caller_identity()["Arn"]


def _error(fn):
    """Call fn(); return (Code, Message) of the ClientError it raises, and fail if it succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
