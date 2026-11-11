"""update-user-attributes-phone-number-applies-immediately-unverified."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-user-attributes-phone-number-applies-immediately-unverified"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_LENIENT_POLICY = {
    "PasswordPolicy": {
        "MinimumLength": 8,
        "RequireUppercase": False,
        "RequireLowercase": False,
        "RequireNumbers": False,
        "RequireSymbols": False,
    }
}
_PASSWORD = "Str0ngPassw0rd!"


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn() raises; a success fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _new_sns_role(ctx):
    """IAM role trusted by cognito-idp.amazonaws.com with sns:Publish, required by
    SmsConfiguration.SnsCallerArn before a pool may auto-verify phone_number."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cip-phoneimm-sns-role-")
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Path="/sim2real/"
    )["Role"]["Arn"]

    def _cleanup():
        try:
            for p in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role_name, PolicyName=p)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "sns:Publish", "Resource": "*"}],
            }
        ),
    )
    return arn


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Without AttributesRequireVerificationBeforeUpdate, a phone_number update applies at once
    as unverified with an SMS code; neither old nor new number signs in until it is verified."""
    c = ctx.client("cognito-idp")
    sns_role_arn = _new_sns_role(ctx)

    def _try_create_pool():
        return c.create_user_pool(
            PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
            UserPoolTags=_TAGS,
            Policies=_LENIENT_POLICY,
            AliasAttributes=["phone_number"],
            AutoVerifiedAttributes=["phone_number"],
            SmsConfiguration={"SnsCallerArn": sns_role_arn, "SnsRegion": ctx.region},
        )["UserPool"]["Id"]

    # The SNS role's trust relationship may not have propagated yet; retry pool creation on
    # any transient rejection instead of sleeping blindly.
    deadline = time.monotonic() + 60
    pool_id = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            pool_id = _try_create_pool()
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(3)
    if pool_id is None:
        raise last_exc
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))

    client_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
        ],
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))

    username = ctx.unique_name("sim2real-behav-cip-phoneuser-")
    old_phone = "+12065550101"
    new_phone = "+12065550102"
    c.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="Temp0rar1Pass!",
        MessageAction="SUPPRESS",
        UserAttributes=[
            {"Name": "phone_number", "Value": old_phone},
            {"Name": "phone_number_verified", "Value": "true"},
        ],
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=_PASSWORD, Permanent=True
    )

    auth = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
    )["AuthenticationResult"]
    access_token = auth["AccessToken"]

    update_resp = c.update_user_attributes(
        AccessToken=access_token,
        UserAttributes=[{"Name": "phone_number", "Value": new_phone}],
    )
    delivery = update_resp.get("CodeDeliveryDetailsList")
    assert delivery and len(delivery) == 1, (
        f"expected exactly 1 code delivery for the phone_number change, got {delivery!r}"
    )
    assert delivery[0]["AttributeName"] == "phone_number", (
        f"expected the code delivery for 'phone_number', got {delivery[0]!r}"
    )
    assert delivery[0]["DeliveryMedium"] == "SMS", (
        f"expected DeliveryMedium 'SMS', got {delivery[0]['DeliveryMedium']!r}"
    )

    # IMMEDIATE: no polling -- the claim under test is that GetUser reflects the new value
    # right after the mutating call returns, not eventually.
    attrs = {a["Name"]: a["Value"] for a in c.get_user(AccessToken=access_token)["UserAttributes"]}
    assert attrs.get("phone_number") == new_phone, (
        f"expected phone_number to apply IMMEDIATELY to {new_phone!r} (not held pending), "
        f"got {attrs.get('phone_number')!r}"
    )
    assert attrs.get("phone_number_verified") == "false", (
        f"expected the newly-applied, not-yet-verified phone_number to read verified=false, "
        f"got {attrs.get('phone_number_verified')!r}"
    )

    # The old alias is overwritten and the new one is not usable until verified.
    old_code, old_message = _error(
        lambda: c.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": old_phone, "PASSWORD": _PASSWORD},
        )
    )
    assert (old_code, old_message) == ("UserNotFoundException", "User does not exist."), (
        f"expected the overwritten old phone_number to no longer resolve as an alias "
        f"(UserNotFoundException 'User does not exist.'), got {old_code!r}: {old_message!r}"
    )
    new_code, new_message = _error(
        lambda: c.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": new_phone, "PASSWORD": _PASSWORD},
        )
    )
    assert (new_code, new_message) == ("UserNotFoundException", "User does not exist."), (
        f"expected the new, unverified phone_number to not yet resolve as a sign-in alias "
        f"(UserNotFoundException 'User does not exist.'), got {new_code!r}: {new_message!r}"
    )

    c.admin_update_user_attributes(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "phone_number_verified", "Value": "true"}],
    )
    verified_attrs = {
        a["Name"]: a["Value"] for a in c.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]
    }
    assert verified_attrs.get("phone_number_verified") == "true", (
        f"expected phone_number_verified=true after AdminUpdateUserAttributes, "
        f"got {verified_attrs.get('phone_number_verified')!r}"
    )
    final = c.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": new_phone, "PASSWORD": _PASSWORD},
    )
    assert final["AuthenticationResult"]["AccessToken"], (
        f"expected sign-in by the new, now-verified phone_number alias to succeed, got {final}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
