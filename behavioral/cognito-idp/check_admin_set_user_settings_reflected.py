"""admin-set-user-settings-reflected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "admin-set-user-settings-reflected"
GROUP = "server-side"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminSetUserSettings/SetUserSettings persisted MFA delivery preferences are reflected in AdminGetUser."""
    cognito = ctx.client("cognito-idp")
    iam = ctx.client("iam")

    # Real Cognito rejects AdminSetUserSettings/SetUserSettings SMS MFA options
    # with InvalidParameterException ("Cannot change the MFA setting when the
    # user pool has no SMS configuration") unless the pool has an SnsCallerArn
    # configured. Create a role Cognito can assume to publish SMS via SNS.
    role_name = ctx.unique_name("sim2real-settings-sms-role")
    external_id = ctx.unique_name("sim2real-settings-extid")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cognito-idp.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    inline_policy_name = "sim2real-settings-sns-publish"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sns:Publish", "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(
            RoleName=role_name, PolicyName=inline_policy_name
        )
    )

    pool_id = _create_user_pool_with_retry(
        cognito,
        pool_name=ctx.unique_name("sim2real-settings-pool"),
        sns_caller_arn=role_arn,
        external_id=external_id,
    )
    ctx.on_cleanup(lambda: _delete_user_pool_with_retry(cognito, pool_id=pool_id))

    # CreateUserPool's top-level SmsConfiguration only wires up SMS for
    # verification/invite messages. Real Cognito additionally requires the
    # user pool's *MFA* configuration (SetUserPoolMfaConfig) to carry an SMS
    # configuration before AdminSetUserSettings/SetUserSettings will accept an
    # SMS MFA option; otherwise it rejects with InvalidParameterException
    # ("Cannot change the MFA setting when the user pool has no SMS
    # configuration configured for MFA"). Enable it explicitly here.
    _set_user_pool_mfa_config_with_retry(
        cognito,
        pool_id=pool_id,
        sns_caller_arn=role_arn,
        external_id=external_id,
    )

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-settings-client"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-settings-user")
    password = "Sim2Real!Str0ng23"

    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "phone_number", "Value": "+15005550006"}],
        MessageAction="SUPPRESS",
    )
    # No per-user cleanup: the pool cleanup deletes the user with it, and the check itself
    # deletes the pool before its final read.
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )

    auth_resp = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = auth_resp["AuthenticationResult"]["AccessToken"]

    # AdminSetUserSettings (admin path) persists SMS MFA option.
    mfa_options = [{"DeliveryMedium": "SMS", "AttributeName": "phone_number"}]
    cognito.admin_set_user_settings(
        UserPoolId=pool_id, Username=username, MFAOptions=mfa_options
    )
    got = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert got.get("MFAOptions") == mfa_options, (
        f"AdminSetUserSettings not reflected in AdminGetUser: {got.get('MFAOptions')!r}"
    )

    # SetUserSettings (self-service path, authorized by access token) clears it back out.
    cognito.set_user_settings(AccessToken=access_token, MFAOptions=[])
    got2 = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert got2.get("MFAOptions") in (None, []), (
        f"SetUserSettings clear not reflected in AdminGetUser: {got2.get('MFAOptions')!r}"
    )

    # Prove the pool is actually gone rather than leaving that only to best-effort cleanup:
    # delete it here, independently, and read it back.
    _delete_user_pool_with_retry(cognito, pool_id=pool_id)
    code, message = _error(lambda: cognito.admin_get_user(UserPoolId=pool_id, Username=username))
    assert code == "ResourceNotFoundException", (
        f"deleted user pool must reject a read with ResourceNotFoundException, got {code!r}"
    )
    expected_message = f"User pool {pool_id} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator accepting what AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_user_pool_with_retry(
    cognito, *, pool_name, sns_caller_arn, external_id, timeout_s=90.0
):
    """create_user_pool validates that Cognito can assume the SnsCallerArn role;
    immediately after IAM create_role/put_role_policy this can fail transiently
    due to IAM eventual consistency (InvalidSmsRoleTrustRelationshipException /
    InvalidSmsRoleAccessPolicyException). Retry within a bound."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return cognito.create_user_pool(
                PoolName=pool_name,
                DeletionProtection="INACTIVE",
                SmsConfiguration={
                    "SnsCallerArn": sns_caller_arn,
                    "ExternalId": external_id,
                },
                UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
            )["UserPool"]["Id"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in (
                "InvalidSmsRoleTrustRelationshipException",
                "InvalidSmsRoleAccessPolicyException",
                "InvalidParameterException",
            ):
                last_err = e
                time.sleep(3.0)
                continue
            raise
    raise AssertionError(f"could not create user pool with SMS config in time: {last_err}")


def _delete_user_pool_with_retry(cognito, *, pool_id, timeout_s=20.0):
    """DeleteUserPool can transiently fail (e.g. ConcurrentModificationException right after
    SetUserPoolMfaConfig/AdminSetUserSettings touched the same pool). Retry within a bound so a
    transient conflict does not silently leak the pool -- ctx.run_cleanups() swallows any exception
    a teardown raises, with no signal beyond a later account scan."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            cognito.delete_user_pool(UserPoolId=pool_id)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return  # already deleted by an earlier call in this same run
            last_err = e
            time.sleep(2.0)
    raise AssertionError(f"could not delete user pool {pool_id} in time: {last_err}")


def _set_user_pool_mfa_config_with_retry(
    cognito, *, pool_id, sns_caller_arn, external_id, timeout_s=90.0
):
    """SetUserPoolMfaConfig validates the SnsCallerArn role the same way
    CreateUserPool does, so it can also transiently fail right after
    IAM create_role/put_role_policy due to IAM eventual consistency."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            cognito.set_user_pool_mfa_config(
                UserPoolId=pool_id,
                SmsMfaConfiguration={
                    "SmsAuthenticationMessage": "Your authentication code is {####}",
                    "SmsConfiguration": {
                        "SnsCallerArn": sns_caller_arn,
                        "ExternalId": external_id,
                    },
                },
                MfaConfiguration="OPTIONAL",
            )
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in (
                "InvalidSmsRoleTrustRelationshipException",
                "InvalidSmsRoleAccessPolicyException",
                "InvalidParameterException",
            ):
                last_err = e
                time.sleep(3.0)
                continue
            raise
    raise AssertionError(f"could not set user pool MFA config in time: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
