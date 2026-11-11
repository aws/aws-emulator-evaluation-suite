"""op-contract-adminSetUserSettings."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-adminSetUserSettings"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminSetUserSettings (deprecated SMS-MFA-options setter) actually writes the
    user's MFAOptions -- turning SMS MFA on then back off is observable on the user
    record, not just a 200 -- and rejects a nonexistent username."""
    cognito = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx, cognito)
    username = ctx.unique_name("sim2real-user-")
    phone_number = "+15555550100"
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="TempPass!23",
        MessageAction="SUPPRESS",
        UserAttributes=[
            {"Name": "phone_number", "Value": phone_number},
            {"Name": "phone_number_verified", "Value": "true"},
        ],
    )
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password="TempPass!23", Permanent=True
    )

    baseline = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert baseline.get("MFAOptions", []) == [], "user should start with no MFA options"

    # success path: turning on SMS MFA is reflected on the user record
    cognito.admin_set_user_settings(
        UserPoolId=pool_id,
        Username=username,
        MFAOptions=[{"DeliveryMedium": "SMS", "AttributeName": "phone_number"}],
    )
    enabled = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert enabled.get("MFAOptions") == [
        {"DeliveryMedium": "SMS", "AttributeName": "phone_number"}
    ], enabled.get("MFAOptions")

    # turning it back off is likewise reflected -- proves the call is not a no-op
    cognito.admin_set_user_settings(UserPoolId=pool_id, Username=username, MFAOptions=[])
    disabled = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert disabled.get("MFAOptions", []) == [], disabled.get("MFAOptions")

    # distinct error boundary: nonexistent username
    code = _client_error(
        lambda: cognito.admin_set_user_settings(
            UserPoolId=pool_id, Username="no-such-user-xyz", MFAOptions=[]
        )
    )
    assert code.get("Code") == "UserNotFoundException", code
    assert code.get("Message") == "User does not exist.", code.get("Message")


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_user_pool(ctx, cognito):
    # MFA must be permitted at the pool level (OPTIONAL/ON) -- a pool with the
    # default MfaConfiguration=OFF rejects AdminSetUserSettings with
    # InvalidParameterException ("Cannot change the MFA setting when the user
    # pool's MFA configuration is OFF"). On real AWS, requesting MfaConfiguration
    # at pool creation ALSO requires phone_number to be auto-verified and a real
    # SmsConfiguration (SnsCallerArn) to be present -- "SMS configuration and Auto
    # verification for phone_number are required for MFA configuration" -- so build
    # a minimal IAM role Cognito can assume to publish SMS and wire it in.
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cognito-sms-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cognito-idp.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sms-publish",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "sns:Publish", "Resource": "*"}],
            }
        ),
    )

    def _cleanup_role():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="sms-publish")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)

    # IAM role creation is eventually consistent -- CreateUserPool can reject the
    # brand-new role as not assumable yet, so retry the pool creation itself until
    # the role has propagated.
    def _try_create():
        return cognito.create_user_pool(
            PoolName=ctx.unique_name("sim2real-pool-"),
            MfaConfiguration="OPTIONAL",
            AutoVerifiedAttributes=["phone_number"],
            SmsConfiguration={"SnsCallerArn": role_arn},
            DeletionProtection="INACTIVE",
            UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        )["UserPool"]

    pool = _poll_until_no_error(_try_create)
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _poll_until_no_error(fn, timeout=60, interval=5):
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            return fn()
        except ClientError as err:
            last_err = err
            time.sleep(interval)
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
