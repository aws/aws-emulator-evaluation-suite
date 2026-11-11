"""alias-exists-on-verify-attribute."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alias-exists-on-verify-attribute"
GROUP = 'user-attributes'
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
    import json

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sns-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "cognito-idp.amazonaws.com"}, "Action": "sts:AssumeRole"}
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


def _poll_until_no_error(fn, timeout_s=60, interval_s=5):
    """IAM role creation is eventually consistent -- the caller that assumes it (here,
    CreateUserPool's SmsConfiguration validation) can reject a brand-new role as not
    assumable yet, so retry the CALL that depends on it rather than sleeping blind."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            last_err = err
            time.sleep(interval_s)
    raise last_err


def _new_pool(ctx, c, **kwargs):
    kwargs.setdefault("Policies", _LENIENT_PASSWORD_POLICY)
    kwargs.setdefault("UserPoolTags", _POOL_TAGS)

    def _try_create():
        return c.create_user_pool(
            PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), **kwargs
        )["UserPool"]["Id"]

    pool_id = _poll_until_no_error(_try_create)
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    return pool_id


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


def _admin_login(c, pool_id, client_id, username, password):
    resp = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert "AuthenticationResult" in resp, f"expected AuthenticationResult, got a challenge: {resp}"
    return resp["AuthenticationResult"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A pending phone_number change that collides with another user's verified alias is refused by
    VerifyUserAttribute with CodeMismatchException (exact message) for a guessed code, and
    phone_number_verified never becomes true."""
    c = ctx.client("cognito-idp")
    sns_role_arn = _new_sns_role(ctx)
    pool_id = _new_pool(
        ctx,
        c,
        AliasAttributes=["phone_number"],
        AutoVerifiedAttributes=["phone_number"],
        SmsConfiguration={"SnsCallerArn": sns_role_arn, "SnsRegion": ctx.region},
    )
    client_id = _new_client(
        ctx, c, pool_id, ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
    )["ClientId"]

    claimed_phone = "+12065550101"
    _new_confirmed_user(ctx, c, pool_id, phone_number=claimed_phone, phone_number_verified="true")

    username_b, password_b = _new_confirmed_user(ctx, c, pool_id)
    auth = _admin_login(c, pool_id, client_id, username_b, password_b)
    access_token = auth["AccessToken"]

    pending = c.update_user_attributes(
        AccessToken=access_token, UserAttributes=[{"Name": "phone_number", "Value": claimed_phone}]
    )
    assert pending.get("CodeDeliveryDetailsList"), (
        f"expected a pending verification code delivery for the phone_number change, got {pending}"
    )

    code, code_msg = _err(
        lambda: c.verify_user_attribute(
            AccessToken=access_token, AttributeName="phone_number", Code="000000"
        )
    )
    assert code == "CodeMismatchException", (
        f"expected the pending, alias-colliding phone_number change with a guessed code to be "
        f"rejected with CodeMismatchException (AWS checks the code before the alias) -- never "
        f"silently verified, got {code}"
    )
    assert code_msg == "Invalid verification code provided, please try again.", (
        f"expected the exact CodeMismatchException message, got {code_msg!r}"
    )

    got = c.get_user(AccessToken=access_token)
    phone_verified = next(
        (a["Value"] for a in got["UserAttributes"] if a["Name"] == "phone_number_verified"), None
    )
    assert phone_verified in (None, "false"), (
        f"the colliding pending phone_number must never become verified, got {phone_verified}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
