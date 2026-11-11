"""code-mismatch-vs-expired-precision."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "code-mismatch-vs-expired-precision"
GROUP = 'overly-permissive'
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
_AUTH_FLOWS = [
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
]


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


_SNS_ROLE_TRANSIENT_CODES = (
    "InvalidSmsRoleTrustRelationshipException",
    "InvalidSmsRoleAccessPolicyException",
    "InvalidParameterException",
)


def _new_pool(ctx, c, *, timeout_s=90.0, **kwargs):
    """CreateUserPool, retried within a bound: Cognito may not yet be able to assume a just-created
    SnsCallerArn role because of IAM eventual consistency."""
    kwargs.setdefault("Policies", _LENIENT_PASSWORD_POLICY)
    kwargs.setdefault("UserPoolTags", _POOL_TAGS)
    pool_name = ctx.unique_name("sim2real-behav-cip-pool-")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            pool_id = c.create_user_pool(PoolName=pool_name, **kwargs)["UserPool"]["Id"]
            ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
            return pool_id
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in _SNS_ROLE_TRANSIENT_CODES:
                last_err = exc
                time.sleep(3.0)
                continue
            raise
    raise AssertionError(f"could not create user pool with SMS config in time: {last_err}")


def _new_client(ctx, c, pool_id, **kwargs):
    kwargs.setdefault("GenerateSecret", False)
    client = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), **kwargs
    )["UserPoolClient"]
    ctx.on_cleanup(
        lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client["ClientId"])
    )
    return client


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
    """A wrong code against an outstanding one is a mismatch (CodeMismatchException, or
    EnableSoftwareTokenMFAException for VerifySoftwareToken), never ExpiredCodeException, while
    ConfirmSignUp where no code was ever issued is ExpiredCodeException."""
    c = ctx.client("cognito-idp")
    sns_role_arn = _new_sns_role(ctx)
    pool_id = _new_pool(
        ctx,
        c,
        AutoVerifiedAttributes=["phone_number"],
        AccountRecoverySetting={
            "RecoveryMechanisms": [{"Priority": 1, "Name": "verified_phone_number"}]
        },
        SmsConfiguration={"SnsCallerArn": sns_role_arn, "SnsRegion": ctx.region},
    )
    client_id = _new_client(ctx, c, pool_id, ExplicitAuthFlows=list(_AUTH_FLOWS))["ClientId"]

    def new_phone_user(phone_number, verified=True):
        username = ctx.unique_name("sim2real-behav-cip-codeprec-user-")
        password = PASSWORD
        c.admin_create_user(
            UserPoolId=pool_id,
            Username=username,
            TemporaryPassword="Temp0rar1Pass!",
            MessageAction="SUPPRESS",
            UserAttributes=[
                {"Name": "phone_number", "Value": phone_number},
                {"Name": "phone_number_verified", "Value": "true" if verified else "false"},
            ],
        )
        ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
        c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
        return username, password

    # -- ConfirmSignUp --
    su_username = ctx.unique_name("sim2real-behav-cip-codeprec-signup-")
    c.sign_up(
        ClientId=client_id,
        Username=su_username,
        Password=PASSWORD,
        UserAttributes=[{"Name": "phone_number", "Value": "+12065550111"}],
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=su_username))
    c1, c1_msg = _err(
        lambda: c.confirm_sign_up(
            ClientId=client_id, Username=su_username, ConfirmationCode="000000"
        )
    )
    assert c1 == "CodeMismatchException", (
        f"ConfirmSignUp: expected CodeMismatchException for a wrong code, got {c1}"
    )
    assert c1_msg == 'Invalid verification code provided, please try again.', f"expected the exact {c1} message, got {c1_msg!r}"
    su_status = c.admin_get_user(UserPoolId=pool_id, Username=su_username)["UserStatus"]
    assert su_status == "UNCONFIRMED", (
        f"ConfirmSignUp: user should remain UNCONFIRMED after a wrong code, got {su_status}"
    )

    # -- ConfirmSignUp, no code ever issued (nothing to auto-verify -> no delivery) --
    ne_username = ctx.unique_name("sim2real-behav-cip-codeprec-noverify-")
    su_none = c.sign_up(ClientId=client_id, Username=ne_username, Password=PASSWORD)
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=ne_username))
    assert "CodeDeliveryDetails" not in su_none, (
        f"SignUp with no auto-verified attribute unexpectedly reported delivery: {su_none}"
    )
    c4, c4_msg = _err(
        lambda: c.confirm_sign_up(
            ClientId=client_id, Username=ne_username, ConfirmationCode="000000"
        )
    )
    assert c4 == "ExpiredCodeException", (
        f"ConfirmSignUp with no code ever issued: expected ExpiredCodeException (no live code to "
        f"compare against), got {c4}"
    )
    assert c4_msg == 'Invalid code provided, please request a code again.', f"expected the exact {c4} message, got {c4_msg!r}"
    ne_status = c.admin_get_user(UserPoolId=pool_id, Username=ne_username)["UserStatus"]
    assert ne_status == "UNCONFIRMED", (
        f"ConfirmSignUp with no code issued: user should remain UNCONFIRMED, got {ne_status}"
    )

    # -- ConfirmForgotPassword --
    fp_username, fp_password = new_phone_user("+12065550112")
    c.forgot_password(ClientId=client_id, Username=fp_username)
    c2, c2_msg = _err(
        lambda: c.confirm_forgot_password(
            ClientId=client_id,
            Username=fp_username,
            ConfirmationCode="000000",
            Password="BrandNewStr0ngPassw0rd!",
        )
    )
    assert c2 == "CodeMismatchException", (
        f"ConfirmForgotPassword: expected CodeMismatchException for a wrong code, got {c2}"
    )
    assert c2_msg == 'Invalid verification code provided, please try again.', f"expected the exact {c2} message, got {c2_msg!r}"
    still_valid = _admin_login(c, pool_id, client_id, fp_username, fp_password)
    assert still_valid["AccessToken"]

    # -- VerifyUserAttribute --
    vu_username, vu_password = new_phone_user("+12065550113", verified=False)
    vu_token = _admin_login(c, pool_id, client_id, vu_username, vu_password)["AccessToken"]
    c.get_user_attribute_verification_code(AccessToken=vu_token, AttributeName="phone_number")
    c3, c3_msg = _err(
        lambda: c.verify_user_attribute(
            AccessToken=vu_token, AttributeName="phone_number", Code="000000"
        )
    )
    assert c3 == "CodeMismatchException", (
        f"VerifyUserAttribute: expected CodeMismatchException for a wrong code, got {c3}"
    )
    assert c3_msg == 'Invalid verification code provided, please try again.', f"expected the exact {c3} message, got {c3_msg!r}"
    vu_attrs = {
        a["Name"]: a["Value"]
        for a in c.admin_get_user(UserPoolId=pool_id, Username=vu_username)["UserAttributes"]
    }
    assert vu_attrs["phone_number_verified"] == "false", (
        f"VerifyUserAttribute: phone_number should remain unverified after a wrong code, "
        f"got {vu_attrs['phone_number_verified']!r}"
    )

    # -- VerifySoftwareToken --
    c.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )
    st_username, st_password = new_phone_user("+12065550114")
    st_token = _admin_login(c, pool_id, client_id, st_username, st_password)["AccessToken"]
    c.associate_software_token(AccessToken=st_token)
    st_code, st_msg = _err(lambda: c.verify_software_token(AccessToken=st_token, UserCode="000000"))
    assert st_code == "EnableSoftwareTokenMFAException", (
        f"VerifySoftwareToken: expected EnableSoftwareTokenMFAException for a wrong code, got {st_code!r}"
    )
    assert st_msg == "Code mismatch", (
        f"VerifySoftwareToken: expected the exact EnableSoftwareTokenMFAException message, got {st_msg!r}"
    )
    mfa_list = c.get_user(AccessToken=st_token).get("UserMFASettingList", [])
    assert "SOFTWARE_TOKEN_MFA" not in mfa_list, (
        f"VerifySoftwareToken: MFA should not be enabled after a wrong code, got {mfa_list}"
    )

    for op_name, code in (("ConfirmSignUp", c1), ("ConfirmForgotPassword", c2), ("VerifyUserAttribute", c3)):
        assert code != "ExpiredCodeException", (
            f"{op_name}: a wrong code must never be conflated with ExpiredCodeException, got {code}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
