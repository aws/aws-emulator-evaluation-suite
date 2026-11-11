"""alias-exists-on-confirm-signup."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alias-exists-on-confirm-signup"
GROUP = 'signup-state-machine'
SERVICES = ['cognito-idp']

_LENIENT_PASSWORD_POLICY = {
    "PasswordPolicy": {
        "MinimumLength": 8,
        "RequireUppercase": False,
        "RequireLowercase": False,
        "RequireNumbers": False,
        "RequireSymbols": False,
    }
}
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
PASSWORD = "Str0ngPassw0rd!"


def _err(fn):
    """Call fn() and return the (code, message) of the ClientError it raises.
    An unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_role(iam, role_name):
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _new_sns_role(ctx):
    """IAM role trusted by cognito-idp.amazonaws.com with sns:Publish, for a pool's
    SmsConfiguration.SnsCallerArn."""
    import json

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sns-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cognito-idp.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": k, "Value": v} for k, v in _POOL_TAGS.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sns:Publish", "Resource": "*"}]}
        ),
    )
    return arn


def _new_pool_retrying_role_propagation(ctx, c, **kwargs):
    """CreateUserPool with a just-created SnsCallerArn: IAM role propagation to the
    cognito-idp.amazonaws.com trust check is eventually consistent, so retry the specific
    "role not yet assumable" errors on a bounded deadline rather than sleeping blind."""
    kwargs.setdefault("Policies", _LENIENT_PASSWORD_POLICY)
    kwargs.setdefault("UserPoolTags", _POOL_TAGS)
    # A pool can default to DeletionProtection=ACTIVE, which makes DeleteUserPool fail and the
    # pool leak; disable it explicitly rather than relying on the default.
    kwargs.setdefault("DeletionProtection", "INACTIVE")
    deadline = time.monotonic() + 60
    while True:
        try:
            pool_id = c.create_user_pool(
                PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), **kwargs
            )["UserPool"]["Id"]
            ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
            return pool_id
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("InvalidSmsRoleTrustRelationshipException", "InvalidSmsRoleAccessPolicyException"):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(3)


def _new_client(ctx, c, pool_id, **kwargs):
    kwargs.setdefault("GenerateSecret", False)
    client = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), **kwargs
    )["UserPoolClient"]
    ctx.on_cleanup(
        lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client["ClientId"])
    )
    return client


def _new_confirmed_user(ctx, c, pool_id, password=PASSWORD, **extra_attrs):
    username = ctx.unique_name("sim2real-behav-cip-user-")
    attrs = [{"Name": "email", "Value": f"{username}@example.com"}]
    attrs.extend({"Name": k, "Value": v} for k, v in extra_attrs.items())
    c.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="Temp0rar1Pass!",
        MessageAction="SUPPRESS",
        UserAttributes=attrs,
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    return username, password


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ConfirmSignUp for a user whose phone_number is already another user's verified alias is
    rejected with CodeMismatchException (exact message) for a guessed code, and the user stays
    UNCONFIRMED; AWS checks the code before the alias, so AliasExistsException is not reachable."""
    c = ctx.client("cognito-idp")
    sns_role_arn = _new_sns_role(ctx)
    pool_id = _new_pool_retrying_role_propagation(
        ctx,
        c,
        AliasAttributes=["phone_number"],
        AutoVerifiedAttributes=["phone_number"],
        SmsConfiguration={"SnsCallerArn": sns_role_arn, "SnsRegion": ctx.region},
    )
    client_id = _new_client(ctx, c, pool_id)["ClientId"]

    claimed_phone = "+12065550100"
    _new_confirmed_user(ctx, c, pool_id, phone_number=claimed_phone, phone_number_verified="true")

    username_b = ctx.unique_name("sim2real-behav-cip-signupb-")
    c.sign_up(
        ClientId=client_id,
        Username=username_b,
        Password=PASSWORD,
        UserAttributes=[{"Name": "phone_number", "Value": claimed_phone}],
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username_b))

    code, code_msg = _err(
        lambda: c.confirm_sign_up(
            ClientId=client_id, Username=username_b, ConfirmationCode="000000"
        )
    )
    assert code == "CodeMismatchException", (
        f"expected confirming sign-up with a guessed code for a phone number already claimed as a "
        f"verified alias elsewhere to be rejected with CodeMismatchException -- never silently "
        f"confirmed, got {code}"
    )
    assert code_msg == "Invalid verification code provided, please try again.", (
        f"expected the exact CodeMismatchException message, got {code_msg!r}"
    )

    status = c.admin_get_user(UserPoolId=pool_id, Username=username_b)["UserStatus"]
    assert status == "UNCONFIRMED", (
        f"a rejected ConfirmSignUp must leave the user UNCONFIRMED, got {status}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
