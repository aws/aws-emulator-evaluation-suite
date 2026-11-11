"""admin-initiate-and-respond-to-auth-challenge-with-event-history."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-initiate-and-respond-to-auth-challenge-with-event-history"
GROUP = 'auth-state-machine'
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


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator accepting what AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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


def _totp_now(secret_b32, digits=6, step=30, offset=0):
    import base64
    import hashlib
    import hmac
    import struct
    import time

    padded = secret_b32.upper()
    padded += "=" * ((8 - len(padded) % 8) % 8)
    key = base64.b32decode(padded)
    counter = int(time.time() // step) + offset
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[o : o + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


def _setup_software_token_mfa(c, access_token):
    secret = c.associate_software_token(AccessToken=access_token)["SecretCode"]
    verify = c.verify_software_token(AccessToken=access_token, UserCode=_totp_now(secret))
    assert verify["Status"] == "SUCCESS", verify
    c.set_user_mfa_preference(
        AccessToken=access_token,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
    )
    return secret


def _new_pool(ctx, c, **kwargs):
    kwargs.setdefault("Policies", _LENIENT_PASSWORD_POLICY)
    kwargs.setdefault("UserPoolTags", _POOL_TAGS)
    pool_id = _retry_throttled(
        lambda: c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), **kwargs)
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _new_client(ctx, c, pool_id, **kwargs):
    kwargs.setdefault("GenerateSecret", False)
    client = _retry_throttled(
        lambda: c.create_user_pool_client(
            UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), **kwargs
        )
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """For a TOTP MFA user, AdminInitiateAuth returns SOFTWARE_TOKEN_MFA without tokens and
    AdminRespondToAuthChallenge with the current code returns tokens; AdminListUserAuthEvents
    without advanced security answers UserPoolAddOnNotEnabledException and the exact message."""
    c = ctx.client("cognito-idp")
    pool_id = _new_pool(ctx, c, AutoVerifiedAttributes=["email"])
    client_id = _new_client(ctx, c, pool_id, ExplicitAuthFlows=list(_AUTH_FLOWS))["ClientId"]
    _retry_throttled(
        lambda: c.set_user_pool_mfa_config(
            UserPoolId=pool_id,
            SoftwareTokenMfaConfiguration={"Enabled": True},
            MfaConfiguration="OPTIONAL",
        )
    )
    username, password = _new_confirmed_user(ctx, c, pool_id)
    bootstrap_auth = _admin_login(c, pool_id, client_id, username, password)
    secret = _setup_software_token_mfa(c, bootstrap_auth["AccessToken"])

    resp = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert resp.get("ChallengeName") == "SOFTWARE_TOKEN_MFA", resp
    assert "AuthenticationResult" not in resp

    # offset=1: the bootstrap VerifySoftwareToken already consumed this window's code, and Cognito
    # rejects immediate reuse -- request the NEXT time-step's code (accepted under +/-1 skew
    # tolerance) rather than sleeping to cross the window boundary.
    code = _totp_now(secret, offset=1)
    final = c.admin_respond_to_auth_challenge(
        UserPoolId=pool_id,
        ClientId=client_id,
        ChallengeName="SOFTWARE_TOKEN_MFA",
        Session=resp["Session"],
        ChallengeResponses={"USERNAME": username, "SOFTWARE_TOKEN_MFA_CODE": code},
    )
    assert "AuthenticationResult" in final, final
    assert final["AuthenticationResult"]["AccessToken"]

    events_code, events_message = _error(
        lambda: c.admin_list_user_auth_events(UserPoolId=pool_id, Username=username)
    )
    assert events_code == "UserPoolAddOnNotEnabledException", (
        f"expected UserPoolAddOnNotEnabledException, got {events_code}"
    )
    expected_events_message = "This is an add on feature. Please update AdvancedSecurityMode for your user pool to access this API."
    assert events_message == expected_events_message, f"expected message {expected_events_message!r}, got {events_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
