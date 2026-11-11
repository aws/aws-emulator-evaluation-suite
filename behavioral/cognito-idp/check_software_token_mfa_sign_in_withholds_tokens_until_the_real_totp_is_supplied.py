"""software-token-mfa-sign-in-withholds-tokens-until-the-real-totp-is-supplied."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "software-token-mfa-sign-in-withholds-tokens-until-the-real-totp-is-supplied"
GROUP = 'state-machine'
SERVICES = ['cognito-idp']

PASSWORD = "Sup3r-Secret-Passw0rd!"
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """With TOTP enrolled, sign-in returns a SOFTWARE_TOKEN_MFA challenge and no tokens; a wrong code fails
    with CodeMismatchException and its exact message and issues nothing, while the code from the
    enrolled secret completes sign-in with a token GetUser accepts."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags=dict(_POOL_TAGS),
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _p=pool_id: c.delete_user_pool(UserPoolId=_p))

    # Enrolment needs MFA OPTIONAL: with the pool already ON, an un-enrolled user is routed to
    # MFA_SETUP instead of signing in, so the pool is flipped to ON after the token is enrolled.
    c.set_user_pool_mfa_config(
        UserPoolId=pool_id, MfaConfiguration="OPTIONAL",
        SoftwareTokenMfaConfiguration={"Enabled": True},
    )

    client_id = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )

    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(
        UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"},
                        {"Name": "email_verified", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True
    )

    access_token = c.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]["AccessToken"]

    secret = c.associate_software_token(AccessToken=access_token)["SecretCode"]
    assert len(base64.b32decode(secret.upper() + "=" * ((8 - len(secret) % 8) % 8))) >= 16, (
        f"AssociateSoftwareToken returned a secret that is not >=128 bits of base32 key "
        f"material: {secret!r}"
    )
    enrol_code = _totp(secret)
    verify = c.verify_software_token(
        AccessToken=access_token, UserCode=enrol_code,
        FriendlyDeviceName="sim2real-behav-authenticator",
    )
    assert verify["Status"] == "SUCCESS", (
        f"the enrolment code derived from the issued secret was not accepted: {verify!r}"
    )
    c.admin_set_user_mfa_preference(
        UserPoolId=pool_id, Username=username,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
    )
    c.set_user_pool_mfa_config(
        UserPoolId=pool_id, MfaConfiguration="ON",
        SoftwareTokenMfaConfiguration={"Enabled": True},
    )

    init = c.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )
    assert init["ChallengeName"] == "SOFTWARE_TOKEN_MFA", (
        f"MFA ON did not force the software-token challenge: {init!r}"
    )
    assert "AuthenticationResult" not in init, (
        f"tokens were issued before MFA was satisfied: {sorted(init)!r}"
    )
    assert init["ChallengeParameters"].get("USER_ID_FOR_SRP") == username, (
        f"the challenge does not identify the user: {init['ChallengeParameters']!r}"
    )

    # --- the one broken thing: a six-digit code that is not derived from the enrolled secret ---
    wrong_code = _a_different_code(secret)
    error_payload = _rejection_response(
        lambda: c.admin_respond_to_auth_challenge(
            UserPoolId=pool_id, ClientId=client_id, ChallengeName="SOFTWARE_TOKEN_MFA",
            Session=init["Session"],
            ChallengeResponses={"USERNAME": username, "SOFTWARE_TOKEN_MFA_CODE": wrong_code},
        )
    )
    code = error_payload["Error"]["Code"]
    assert code == "CodeMismatchException", (
        f"a six-digit code not derived from the enrolled secret was not refused with the exact "
        f"code: {code!r} (full payload {error_payload!r})"
    )
    message = error_payload["Error"].get("Message", "")
    expected_message = "Invalid code received for user"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    assert "AuthenticationResult" not in error_payload, (
        f"tokens accompanied the refused MFA code: {sorted(error_payload)!r}"
    )

    # --- positive control: the code derived from that same secret, in the same file ---
    control_init = c.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )
    assert control_init["ChallengeName"] == "SOFTWARE_TOKEN_MFA", (
        f"the control sign-in was not challenged: {control_init!r}"
    )
    # Cognito refuses a code it has already consumed, so wait for the 30 s step to roll over
    # rather than replaying the enrolment code. This polls the derived code, not the clock.
    control_code = _wait_for_new_totp_code(secret, enrol_code)
    done = c.admin_respond_to_auth_challenge(
        UserPoolId=pool_id, ClientId=client_id, ChallengeName="SOFTWARE_TOKEN_MFA",
        Session=control_init["Session"],
        ChallengeResponses={"USERNAME": username, "SOFTWARE_TOKEN_MFA_CODE": control_code},
    )
    token = done.get("AuthenticationResult", {}).get("AccessToken")
    assert token, (
        f"a valid TOTP did not complete the sign-in, so the refusal above is not specific: "
        f"{done!r}"
    )
    who = c.get_user(AccessToken=token)
    assert who["Username"] == username, (
        f"the post-MFA token is not usable against GetUser: {who!r}"
    )


def _rejection_response(fn) -> dict:
    """Return the full botocore error response of a call expected to be REJECTED.

    Raises when the call succeeds, so an accepted call never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, which is the defect: {result!r}"
    )


def _totp(secret_b32: str, digits: int = 6, step: int = 30, offset: int = 0) -> str:
    """RFC 6238 TOTP over a base32 secret; `offset` shifts the time-step counter."""
    padded = secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(padded)
    counter = int(time.time() // step) + offset
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code_int).zfill(digits)


def _a_different_code(secret_b32: str) -> str:
    """A syntactically valid six-digit code that is NOT this secret's code for any step near
    now. Derived by walking candidates rather than hardcoding one, so the negative can never
    accidentally be the right answer."""
    nearby = {_totp(secret_b32, offset=o) for o in range(-4, 5)}
    for candidate in range(0, 1000000):
        text = str(candidate).zfill(6)
        if text not in nearby:
            return text
    raise AssertionError("no six-digit code outside the nearby TOTP window exists")


def _wait_for_new_totp_code(secret_b32: str, previous_code: str, timeout_s: float = 45.0) -> str:
    """Poll the derived code until the 30 s step rolls it over, so the control leg presents a
    code Cognito has not already consumed. The observable condition is the code changing."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        code = _totp(secret_b32)
        if code != previous_code:
            return code
        time.sleep(1.0)
    raise AssertionError(
        f"the TOTP step never rolled over within {timeout_s}s, so no unconsumed code could be "
        f"presented (previous was {previous_code!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
