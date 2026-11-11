"""op-contract-set-user-settings."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-set-user-settings"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetUserSettings writes the caller's MFAOptions: turning SMS MFA on then off is visible via
    GetUser, and a garbage access token is rejected with NotAuthorizedException."""
    cognito = ctx.client("cognito-idp")

    pool_id, client_id = _create_pool_and_client(ctx)
    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real!Test123"
    phone_number = "+15555550100"

    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
        UserAttributes=[
            {"Name": "phone_number", "Value": phone_number},
            {"Name": "phone_number_verified", "Value": "true"},
        ],
    )
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )

    auth = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = auth["AuthenticationResult"]["AccessToken"]

    baseline = cognito.get_user(AccessToken=access_token)
    assert baseline.get("MFAOptions", []) == [], "user should start with no MFA options"

    mfa_options = [{"DeliveryMedium": "SMS", "AttributeName": "phone_number"}]
    cognito.set_user_settings(AccessToken=access_token, MFAOptions=mfa_options)
    enabled = cognito.get_user(AccessToken=access_token)
    assert enabled.get("MFAOptions") == mfa_options, enabled.get("MFAOptions")

    cognito.set_user_settings(AccessToken=access_token, MFAOptions=[])
    disabled = cognito.get_user(AccessToken=access_token)
    assert disabled.get("MFAOptions", []) == [], disabled.get("MFAOptions")

    code, message = _error(
        lambda: cognito.set_user_settings(AccessToken="not-a-real-token", MFAOptions=[])
    )
    assert code == "NotAuthorizedException", code
    expected = "Invalid Access Token"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _create_pool_and_client(ctx):
    from botocore.exceptions import ClientError

    cognito = ctx.client("cognito-idp")
    iam = ctx.client("iam")

    # SetUserSettings rejects an SMS MFAOptions write with InvalidParameterException
    # ("Cannot change the MFA setting when the user pool has no SMS configuration
    # configured for MFA") unless the pool's MFA config carries a real SnsCallerArn.
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
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
            PoolName=ctx.unique_name("sim2real-behav-usersettings-"),
            MfaConfiguration="OPTIONAL",
            AutoVerifiedAttributes=["phone_number"],
            SmsConfiguration={"SnsCallerArn": role_arn},
        )["UserPool"]

    pool = _poll_until_no_error(_try_create)
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    return pool_id, client_id


def _poll_until_no_error(fn, timeout=60, interval=5):
    from botocore.exceptions import ClientError

    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            return fn()
        except ClientError as err:
            last_err = err
            time.sleep(interval)
    raise last_err


def _error(fn):
    """Call fn() and return its error (code, message); raise if the call unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
