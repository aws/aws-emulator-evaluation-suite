"""code-delivery-failure-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "code-delivery-failure-error"
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


def _attempt(fn):
    """("ok", None) if fn() succeeds, else ("error", <its botocore Error dict>)."""
    try:
        fn()
    except ClientError as exc:
        return "error", exc.response.get("Error", {})
    return "ok", None


def _error(fn):
    """The botocore Error dict of the expected refusal; an unexpected success raises."""
    kind, err = _attempt(fn)
    if kind == "ok":
        raise AssertionError("expected the call to be refused, but it succeeded")
    return err


def _code(outcome):
    """None for a success, else the refusal's error code."""
    kind, err = outcome
    return None if kind == "ok" else err.get("Code")


def _retry_throttled(fn, *, max_attempts=8, base_delay=1.0):
    import time

    delay = base_delay
    for attempt in range(max_attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "TooManyRequestsException" and attempt < max_attempts - 1:
                time.sleep(delay)
                delay = min(delay * 1.7, 15.0)
                continue
            raise


def _new_pool(ctx, c, **kwargs):
    kwargs.setdefault("Policies", _LENIENT_PASSWORD_POLICY)
    kwargs.setdefault("UserPoolTags", _POOL_TAGS)
    # DeletionProtection=ACTIVE would make the cleanup DeleteUserPool fail.
    kwargs.setdefault("DeletionProtection", "INACTIVE")
    pool_id = _retry_throttled(
        lambda: c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), **kwargs)
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _retry_throttled(lambda: c.delete_user_pool(UserPoolId=pool_id)))
    return pool_id


def _new_client(ctx, c, pool_id, **kwargs):
    kwargs.setdefault("GenerateSecret", False)
    client = _retry_throttled(
        lambda: c.create_user_pool_client(
            UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), **kwargs
        )
    )["UserPoolClient"]
    ctx.on_cleanup(
        lambda: _retry_throttled(
            lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client["ClientId"])
        )
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
    ctx.on_cleanup(
        lambda: _retry_throttled(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    )
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    return username, password


def _user_login(c, client_id, username, password):
    resp = c.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert "AuthenticationResult" in resp, f"expected AuthenticationResult, got a challenge: {resp}"
    return resp["AuthenticationResult"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Code requests with no destination (SMS without phone_number, a verification code for an
    unset attribute) fail with InvalidParameterException; deliverable SignUp/Resend/ForgotPassword
    succeed or hit the daily quota, user status is unchanged, and SetRiskConfiguration persists."""
    c = ctx.client("cognito-idp")
    pool_id = _new_pool(ctx, c, AutoVerifiedAttributes=["email"])
    client_id = _new_client(
        ctx, c, pool_id, ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH"]
    )["ClientId"]

    # SignUp on a deliverable email: success or the documented daily-quota LimitExceededException
    # (which still creates the UNCONFIRMED user).
    signup_username = ctx.unique_name("sim2real-behav-cip-cdf-signup-")
    signup_code = _code(_attempt(
        lambda: c.sign_up(
            ClientId=client_id,
            Username=signup_username,
            Password=PASSWORD,
            UserAttributes=[{"Name": "email", "Value": f"{signup_username}@example.com"}],
        )
    ))
    assert signup_code in (None, "LimitExceededException"), (
        f"SignUp: expected success or a documented daily-quota LimitExceededException, "
        f"got {signup_code}"
    )
    ctx.on_cleanup(
        lambda: _retry_throttled(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=signup_username))
    )

    # ResendConfirmationCode on that UNCONFIRMED user, only if SignUp actually left one behind.
    if _attempt(lambda: c.admin_get_user(UserPoolId=pool_id, Username=signup_username))[0] == "ok":
        resend_code = _code(_attempt(
            lambda: c.resend_confirmation_code(ClientId=client_id, Username=signup_username)
        ))
        assert resend_code in (None, "LimitExceededException"), (
            f"ResendConfirmationCode: expected success or a documented daily-quota "
            f"LimitExceededException, got {resend_code}"
        )
        still_unconfirmed = c.admin_get_user(UserPoolId=pool_id, Username=signup_username)
        assert still_unconfirmed["UserStatus"] == "UNCONFIRMED", still_unconfirmed["UserStatus"]

    # AdminCreateUser: SMS requested for a user with NO phone_number -- caught at validation time.
    admin_username = ctx.unique_name("sim2real-behav-cip-cdf-admin-")
    err1 = _error(
        lambda: c.admin_create_user(
            UserPoolId=pool_id,
            Username=admin_username,
            DesiredDeliveryMediums=["SMS"],
            UserAttributes=[{"Name": "email", "Value": f"{admin_username}@example.com"}],
        )
    )
    assert err1.get("Code") == "InvalidParameterException", (
        f"AdminCreateUser: expected InvalidParameterException, got {err1}"
    )
    expected1 = "No phone_number provided but desired delivery medium was SMS"
    assert err1.get("Message") == expected1, (err1.get("Message"), expected1)
    ctx.on_cleanup(
        lambda: _retry_throttled(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=admin_username))
    )

    # The email request is the control showing the operation itself is not always rejected.
    confirmed_username, confirmed_password = _new_confirmed_user(ctx, c, pool_id, email_verified="true")
    auth = _user_login(c, client_id, confirmed_username, confirmed_password)
    positive_code = _code(_attempt(
        lambda: c.get_user_attribute_verification_code(
            AccessToken=auth["AccessToken"], AttributeName="email"
        )
    ))
    assert positive_code in (None, "LimitExceededException"), (
        f"GetUserAttributeVerificationCode: expected success (or a documented daily-quota "
        f"LimitExceededException) for an attribute the user has, got {positive_code}"
    )
    err2 = _error(
        lambda: c.get_user_attribute_verification_code(
            AccessToken=auth["AccessToken"], AttributeName="phone_number"
        )
    )
    assert err2.get("Code") == "InvalidParameterException", (
        f"GetUserAttributeVerificationCode: expected InvalidParameterException, got {err2}"
    )
    expected2 = "User does not have a valid registered phone number"
    assert err2.get("Message") == expected2, (err2.get("Message"), expected2)
    still_there = c.admin_get_user(UserPoolId=pool_id, Username=confirmed_username)
    assert still_there["UserStatus"] == "CONFIRMED", (
        f"a verification-code delivery failure must not corrupt UserStatus: "
        f"{still_there['UserStatus']}"
    )

    code3 = _code(_attempt(lambda: c.forgot_password(ClientId=client_id, Username=confirmed_username)))
    assert code3 in (None, "LimitExceededException"), (
        f"ForgotPassword: expected success or a documented daily-quota LimitExceededException, "
        f"got {code3}"
    )
    still_confirmed = c.admin_get_user(UserPoolId=pool_id, Username=confirmed_username)
    assert still_confirmed["UserStatus"] == "CONFIRMED", (
        f"a ForgotPassword attempt must not change UserStatus: {still_confirmed['UserStatus']}"
    )

    _retry_throttled(
        lambda: c.set_risk_configuration(
            UserPoolId=pool_id,
            ClientId=client_id,
            AccountTakeoverRiskConfiguration={
                "Actions": {
                    "LowAction": {"Notify": False, "EventAction": "NO_ACTION"},
                    "MediumAction": {"Notify": False, "EventAction": "NO_ACTION"},
                    "HighAction": {"Notify": False, "EventAction": "NO_ACTION"},
                }
            },
        )
    )
    risk_desc = c.describe_risk_configuration(UserPoolId=pool_id, ClientId=client_id)[
        "RiskConfiguration"
    ]
    risk_actions = risk_desc["AccountTakeoverRiskConfiguration"]["Actions"]
    for level in ("LowAction", "MediumAction", "HighAction"):
        assert risk_actions[level]["EventAction"] == "NO_ACTION", (
            f"DescribeRiskConfiguration: expected {level}.EventAction == NO_ACTION, "
            f"got {risk_actions[level]}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
