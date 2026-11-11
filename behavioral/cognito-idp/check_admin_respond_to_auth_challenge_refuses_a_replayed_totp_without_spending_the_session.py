"""admin-respond-to-auth-challenge-refuses-a-replayed-totp-without-spending-the-session."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-respond-to-auth-challenge-refuses-a-replayed-totp-without-spending-the-session"
GROUP = "auth-state-machine"
SERVICES = ["cognito-idp"]

PASSWORD = "Sim2Real-Behav-Pass-1!"
AUTH_FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
_REPLAYED = ("ExpiredCodeException", "Your software token has already been used once.")


# timing:real-time — ttl: 24 s https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa-totp.html
@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A TOTP code already spent (by VerifySoftwareToken, or by completing a SOFTWARE_TOKEN_MFA
    challenge) is refused as used once, and the refused session stays live: the next 30 s window's
    code completes that same session."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    c.set_user_pool_mfa_config(UserPoolId=pool_id, MfaConfiguration="OPTIONAL",
                               SoftwareTokenMfaConfiguration={"Enabled": True})
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        GenerateSecret=False, ExplicitAuthFlows=AUTH_FLOWS,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    username = ctx.unique_name("sim2real-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True)

    def initiate():
        return c.admin_initiate_auth(
            UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
        )

    def respond(session, code):
        return c.admin_respond_to_auth_challenge(
            UserPoolId=pool_id, ClientId=client_id, ChallengeName="SOFTWARE_TOKEN_MFA", Session=session,
            ChallengeResponses={"USERNAME": username, "SOFTWARE_TOKEN_MFA_CODE": code},
        )

    access_token = initiate()["AuthenticationResult"]["AccessToken"]
    secret = c.associate_software_token(AccessToken=access_token)["SecretCode"]
    enrol_code = _totp_now(secret)
    verified = c.verify_software_token(AccessToken=access_token, UserCode=enrol_code)
    assert verified["Status"] == "SUCCESS", f"VerifySoftwareToken status {verified.get('Status')!r}"
    c.set_user_mfa_preference(AccessToken=access_token,
                              SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True})

    first = initiate()
    assert first.get("ChallengeName") == "SOFTWARE_TOKEN_MFA", f"expected SOFTWARE_TOKEN_MFA, got {first.get('ChallengeName')!r}"
    expect_error(lambda: respond(first["Session"], enrol_code), *_REPLAYED)

    next_code = _next_window_code(secret, enrol_code)
    done = respond(first["Session"], next_code)["AuthenticationResult"]
    assert done["TokenType"] == "Bearer", f"TokenType is {done.get('TokenType')!r}"
    me = c.get_user(AccessToken=done["AccessToken"])
    assert me["Username"] == username, f"the completed session's access token resolved to {me.get('Username')!r}"

    second = initiate()
    assert second.get("ChallengeName") == "SOFTWARE_TOKEN_MFA", (
        f"second sign-in: expected SOFTWARE_TOKEN_MFA, got {second.get('ChallengeName')!r}"
    )
    expect_error(lambda: respond(second["Session"], next_code), *_REPLAYED)


def _next_window_code(secret_b32: str, spent: str, budget_s: float = 40.0) -> str:
    """Poll the TOTP clock until its code differs from ``spent`` (the next 30 s window)."""
    deadline = time.monotonic() + budget_s
    while time.monotonic() < deadline:
        code = _totp_now(secret_b32)
        if code != spent:
            return code
        time.sleep(1)
    raise AssertionError(f"the TOTP code did not change within {budget_s}s")


def _totp_now(secret_b32: str, digits: int = 6, period: int = 30) -> str:
    padded = secret_b32.upper()
    padded += "=" * ((8 - len(padded) % 8) % 8)
    key = base64.b32decode(padded)
    digest = hmac.new(key, struct.pack(">Q", int(time.time() // period)), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: keys {sorted(result)!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
