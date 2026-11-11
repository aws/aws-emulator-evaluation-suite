"""invalid-lambda-response-error."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-lambda-response-error"
GROUP = 'error-semantics'
SERVICES = ['cognito-idp']

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


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError("real AWS rejects this call, but it SUCCEEDED")


def _assert_succeeds(fn, msg):
    try:
        return fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        raise AssertionError(f"{msg}: expected success, got {code}") from exc


def _reset_password_code(idp, pool_id, username, max_attempts=6, base_delay=5.0):
    """Call AdminResetUserPassword, retrying only the per-account LimitExceededException throttle;
    return (code, message) on error or (None, None) on success."""
    delay = base_delay
    for attempt in range(max_attempts):
        try:
            idp.admin_reset_user_password(UserPoolId=pool_id, Username=username)
            return None, None
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "LimitExceededException" or attempt == max_attempts - 1:
                return code, exc.response.get("Error", {}).get("Message", "")
            time.sleep(delay)
            delay = min(delay * 2, 60.0)


def _new_confirmed_user(ctx, c, pool_id, **extra_attrs):
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
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password="Str0ngPassw0rd!", Permanent=True
    )
    return username, "Str0ngPassw0rd!"


def _new_sns_role(ctx):
    """Create an IAM role trusted by cognito-idp.amazonaws.com with sns:Publish, for SnsCallerArn."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cip-sns-role-")
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


def _new_lambda_trigger_returning_junk(ctx):
    """Create a Lambda that corrupts the response/envelope field Cognito validates for the
    invoking trigger, so the triggering operation fails with InvalidLambdaResponseException."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cip-lambda-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Path="/sim2real/"
    )["Role"]["Arn"]

    def _cleanup_role():
        try:
            for p in iam.list_attached_role_policies(RoleName=role_name).get(
                "AttachedPolicies", []
            ):
                iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )

    handler_src = (
        "def handler(event, context):\n"
        "    ts = event.get('triggerSource', '')\n"
        "    resp = event.get('response') or {}\n"
        "    if ts.startswith('PreSignUp'):\n"
        "        resp['autoConfirmUser'] = 'not-a-boolean'\n"
        "        event['response'] = resp\n"
        "    elif ts.startswith('TokenGeneration'):\n"
        "        resp['claimsOverrideDetails'] = 'not-an-object'\n"
        "        event['response'] = resp\n"
        "    else:\n"
        "        event['userName'] = 12345\n"
        "    return event\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("index.py", handler_src)

    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-behav-cip-trigger-")
    deadline = time.monotonic() + 45
    last_exc = None
    fn_resp = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            fn_resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": buf.getvalue()},
                Timeout=10,
            )
            break
        except Exception as exc:  # noqa: BLE001 - role propagation retry
            last_exc = exc
            time.sleep(3)
    if fn_resp is None:
        raise last_exc
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    return fn_resp["FunctionArn"]


def _poll_until(fn, pred, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    val = None
    while time.monotonic() < deadline:
        val = fn()
        if pred(val):
            return val
        time.sleep(interval_s)
    raise AssertionError(f"poll condition not met within {timeout_s}s: {description}")


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A malformed PreSignUp, PostConfirmation, PreAuthentication, CustomMessage or
    PreTokenGeneration trigger response fails the triggering call with
    InvalidLambdaResponseException; each call succeeds without the trigger and after clearing it."""
    c = ctx.client("cognito-idp")
    fn_arn = _new_lambda_trigger_returning_junk(ctx)
    sns_role_arn = _new_sns_role(ctx)

    # The SNS role's trust relationship may not have propagated yet; retry the
    # pool creation on any transient rejection instead of sleeping blindly.
    pool_deadline = time.monotonic() + 30
    pool_id = None
    last_pool_exc = None
    while time.monotonic() < pool_deadline:
        try:
            pool_id = c.create_user_pool(
                PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
                UserPoolTags=_TAGS,
                Policies=_LENIENT_POLICY,
                AutoVerifiedAttributes=["email"],
                SmsConfiguration={"SnsCallerArn": sns_role_arn},
            )["UserPool"]["Id"]
            break
        except ClientError as exc:  # noqa: BLE001 - SNS role propagation retry
            last_pool_exc = exc
            time.sleep(3)
    if pool_id is None:
        raise last_pool_exc
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    pool_arn = c.describe_user_pool(UserPoolId=pool_id)["UserPool"]["Arn"]

    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=fn_arn.split(":")[-1],
        StatementId=ctx.unique_name("invoke-")[:100],
        Action="lambda:InvokeFunction",
        Principal="cognito-idp.amazonaws.com",
        SourceArn=pool_arn,
    )

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

    # AdminCreateUser: PreSignUp fires (and returns junk) before the user is created.
    # Positive control first, so a target that rejects every AdminCreateUser with any
    # PreSignUp trigger configured -- regardless of what the trigger returns -- cannot
    # pass this leg.
    presignup_control_username = ctx.unique_name("sim2real-behav-cip-lambda-presignup-ctl-")
    _assert_succeeds(
        lambda: c.admin_create_user(
            UserPoolId=pool_id,
            Username=presignup_control_username,
            MessageAction="SUPPRESS",
            UserAttributes=[
                {"Name": "email", "Value": f"{presignup_control_username}@example.com"}
            ],
        ),
        "AdminCreateUser (no trigger) positive control",
    )
    ctx.on_cleanup(
        lambda: c.admin_delete_user(UserPoolId=pool_id, Username=presignup_control_username)
    )

    c.update_user_pool(UserPoolId=pool_id, LambdaConfig={"PreSignUp": fn_arn})
    presignup_username = ctx.unique_name("sim2real-behav-cip-lambda-presignup-")
    presignup_call = lambda: c.admin_create_user(  # noqa: E731
        UserPoolId=pool_id,
        Username=presignup_username,
        MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": f"{presignup_username}@example.com"}],
    )
    code1, message1 = _error(presignup_call)
    assert code1 == "InvalidLambdaResponseException", (
        f"AdminCreateUser (PreSignUp): expected InvalidLambdaResponseException, got {code1}"
    )
    expected_message1 = "Unrecognizable lambda output"
    assert message1 == expected_message1, (
        f"expected message {expected_message1!r}, got {message1!r}"
    )
    # Effect absent: the rejected user must not exist.
    absent1, absent1_message = _error(
        lambda: c.admin_get_user(UserPoolId=pool_id, Username=presignup_username)
    )
    assert absent1 == "UserNotFoundException", (
        f"AdminCreateUser (PreSignUp) rejected but admin_get_user returned {absent1!r}, "
        f"not UserNotFoundException"
    )
    expected_absent1_message = "User does not exist."
    assert absent1_message == expected_absent1_message, (
        f"expected message {expected_absent1_message!r}, got {absent1_message!r}"
    )

    # Restore: clearing the trigger lets the identical call succeed.
    c.update_user_pool(UserPoolId=pool_id, LambdaConfig={})
    _assert_succeeds(presignup_call, "AdminCreateUser (PreSignUp restored)")
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=presignup_username))

    # AdminConfirmSignUp: PostConfirmation fires as the LAST step of confirmation.
    # Positive control on its own unconfirmed user, so a target that rejects every
    # AdminConfirmSignUp with any PostConfirmation trigger configured cannot pass.
    c.update_user_pool(UserPoolId=pool_id, LambdaConfig={})
    confirm_control_username = ctx.unique_name("sim2real-behav-cip-lambda-postconfirm-ctl-")
    c.sign_up(
        ClientId=client_id,
        Username=confirm_control_username,
        Password="Str0ngPassw0rd!",
        UserAttributes=[{"Name": "email", "Value": f"{confirm_control_username}@example.com"}],
    )
    ctx.on_cleanup(
        lambda: c.admin_delete_user(UserPoolId=pool_id, Username=confirm_control_username)
    )
    _assert_succeeds(
        lambda: c.admin_confirm_sign_up(UserPoolId=pool_id, Username=confirm_control_username),
        "AdminConfirmSignUp (no trigger) positive control",
    )

    confirm_username = ctx.unique_name("sim2real-behav-cip-lambda-postconfirm-")
    c.sign_up(
        ClientId=client_id,
        Username=confirm_username,
        Password="Str0ngPassw0rd!",
        UserAttributes=[{"Name": "email", "Value": f"{confirm_username}@example.com"}],
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=confirm_username))
    c.update_user_pool(UserPoolId=pool_id, LambdaConfig={"PostConfirmation": fn_arn})
    code2, message2 = _error(
        lambda: c.admin_confirm_sign_up(UserPoolId=pool_id, Username=confirm_username)
    )
    assert code2 == "InvalidLambdaResponseException", (
        f"AdminConfirmSignUp (PostConfirmation): expected InvalidLambdaResponseException, got {code2}"
    )
    expected_message2 = "Invalid user name. User name in Lambda mismatches the actual username."
    assert message2 == expected_message2, (
        f"expected message {expected_message2!r}, got {message2!r}"
    )
    # PostConfirmation fires after confirmation commits, so the user is CONFIRMED even
    # though the call raised; the error does not roll it back.
    status2 = c.admin_get_user(UserPoolId=pool_id, Username=confirm_username)["UserStatus"]
    assert status2 == "CONFIRMED", (
        f"AdminConfirmSignUp (PostConfirmation) rejected but UserStatus is {status2!r}, "
        f"not CONFIRMED"
    )

    # Restore, on a fresh unconfirmed user (confirm_username is already CONFIRMED and
    # cannot be confirmed again): clearing the trigger lets AdminConfirmSignUp succeed.
    confirm_restore_username = ctx.unique_name("sim2real-behav-cip-lambda-postconfirm-rst-")
    c.sign_up(
        ClientId=client_id,
        Username=confirm_restore_username,
        Password="Str0ngPassw0rd!",
        UserAttributes=[{"Name": "email", "Value": f"{confirm_restore_username}@example.com"}],
    )
    ctx.on_cleanup(
        lambda: c.admin_delete_user(UserPoolId=pool_id, Username=confirm_restore_username)
    )
    c.update_user_pool(UserPoolId=pool_id, LambdaConfig={})
    _assert_succeeds(
        lambda: c.admin_confirm_sign_up(UserPoolId=pool_id, Username=confirm_restore_username),
        "AdminConfirmSignUp (PostConfirmation restored)",
    )

    # AdminInitiateAuth: PreAuthentication fires before credentials are evaluated.
    # Positive control with the same credentials before the trigger is broken, so a
    # target that rejects every AdminInitiateAuth with any PreAuthentication trigger
    # configured cannot pass.
    c.update_user_pool(UserPoolId=pool_id, LambdaConfig={})
    auth_username, auth_password = _new_confirmed_user(ctx, c, pool_id)
    auth_call = lambda: c.admin_initiate_auth(  # noqa: E731
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": auth_username, "PASSWORD": auth_password},
    )
    _assert_succeeds(auth_call, "AdminInitiateAuth (no trigger) positive control")

    c.update_user_pool(UserPoolId=pool_id, LambdaConfig={"PreAuthentication": fn_arn})
    code3, message3 = _error(auth_call)
    assert code3 == "InvalidLambdaResponseException", (
        f"AdminInitiateAuth (PreAuthentication): expected InvalidLambdaResponseException, got {code3}"
    )
    expected_message3 = "Invalid user name. User name in Lambda mismatches the actual username."
    assert message3 == expected_message3, (
        f"expected message {expected_message3!r}, got {message3!r}"
    )

    # Restore: clearing the trigger lets the identical call succeed again.
    c.update_user_pool(UserPoolId=pool_id, LambdaConfig={})
    _assert_succeeds(auth_call, "AdminInitiateAuth (PreAuthentication restored)")

    # AdminResetUserPassword: CustomMessage fires while composing the reset-code
    # notification. Delivered by SMS (phone-verified users) to avoid the account's
    # daily COGNITO_DEFAULT email quota. Two separate
    # users -- one for the positive control, one for the break/restore -- so a
    # target that rejects every AdminResetUserPassword with any CustomMessage
    # trigger configured cannot pass, and so the effect-absent read isn't
    # confused by the control's own status transition.
    reset_control_username, _ = _new_confirmed_user(
        ctx, c, pool_id, phone_number="+12025550123", phone_number_verified="true"
    )
    reset_username, _ = _new_confirmed_user(
        ctx, c, pool_id, phone_number="+12025550124", phone_number_verified="true"
    )
    c.update_user_pool(
        UserPoolId=pool_id,
        AccountRecoverySetting={
            "RecoveryMechanisms": [{"Priority": 1, "Name": "verified_phone_number"}]
        },
    )

    control_code, _ = _reset_password_code(c, pool_id, reset_control_username)
    assert control_code is None, (
        f"AdminResetUserPassword (no trigger) positive control: expected success, "
        f"got {control_code}"
    )

    c.update_user_pool(UserPoolId=pool_id, LambdaConfig={"CustomMessage": fn_arn})
    # Wait for the LambdaConfig change to actually be reflected before relying on it.
    _poll_until(
        lambda: c.describe_user_pool(UserPoolId=pool_id)["UserPool"]
        .get("LambdaConfig", {})
        .get("CustomMessage"),
        lambda arn: arn == fn_arn,
        timeout_s=30,
        interval_s=2,
        description="CustomMessage LambdaConfig change reflected",
    )
    code4, message4 = _reset_password_code(c, pool_id, reset_username)
    assert code4 == "InvalidLambdaResponseException", (
        f"AdminResetUserPassword (CustomMessage): expected InvalidLambdaResponseException, got {code4}"
    )
    expected_message4 = "Invalid user name. User name in Lambda mismatches the actual username."
    assert message4 == expected_message4, (
        f"expected message {expected_message4!r}, got {message4!r}"
    )
    # Effect absent: the reset must not have advanced -- the user is still CONFIRMED.
    status4 = c.admin_get_user(UserPoolId=pool_id, Username=reset_username)["UserStatus"]
    assert status4 == "CONFIRMED", (
        f"AdminResetUserPassword (CustomMessage) rejected but UserStatus is {status4!r}, "
        f"not CONFIRMED"
    )

    # Restore: clearing the trigger lets the identical call succeed.
    c.update_user_pool(UserPoolId=pool_id, LambdaConfig={})
    restored_code, _ = _reset_password_code(c, pool_id, reset_username)
    assert restored_code is None, (
        f"AdminResetUserPassword (CustomMessage restored): expected success, got {restored_code}"
    )

    # GetTokensFromRefreshToken: PreTokenGeneration fires while minting tokens.
    # Positive control on the same refresh token before the trigger is broken (the
    # client has no RefreshTokenRotation configured, so the token stays valid across
    # calls), so a target that rejects every GetTokensFromRefreshToken with any
    # PreTokenGeneration trigger configured cannot pass.
    c.update_user_pool(UserPoolId=pool_id, LambdaConfig={})
    refresh_username, refresh_password = _new_confirmed_user(ctx, c, pool_id)
    fresh_auth = c.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": refresh_username, "PASSWORD": refresh_password},
    )["AuthenticationResult"]
    refresh_call = lambda: c.get_tokens_from_refresh_token(  # noqa: E731
        RefreshToken=fresh_auth["RefreshToken"], ClientId=client_id
    )
    _assert_succeeds(refresh_call, "GetTokensFromRefreshToken (no trigger) positive control")

    c.update_user_pool(UserPoolId=pool_id, LambdaConfig={"PreTokenGeneration": fn_arn})
    code5, message5 = _error(refresh_call)
    assert code5 == "InvalidLambdaResponseException", (
        f"GetTokensFromRefreshToken (PreTokenGeneration): expected "
        f"InvalidLambdaResponseException, got {code5}"
    )
    expected_message5 = "Unrecognizable lambda output"
    assert message5 == expected_message5, (
        f"expected message {expected_message5!r}, got {message5!r}"
    )

    # Restore: clearing the trigger lets the identical call succeed again.
    c.update_user_pool(UserPoolId=pool_id, LambdaConfig={})
    _assert_succeeds(refresh_call, "GetTokensFromRefreshToken (PreTokenGeneration restored)")


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
