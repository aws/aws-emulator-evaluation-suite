"""e2e-mfa-enrollment-then-enforced-login-requires-code."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-mfa-enrollment-then-enforced-login-requires-code"
GROUP = "e2e"
SERVICES = ["cognito-idp"]

_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Enrolling and preferring software-token MFA makes every later InitiateAuth issue a
    SOFTWARE_TOKEN_MFA challenge; a wrong TOTP code is rejected and login only completes
    with a valid one."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-mfa-pool-"), UserPoolTags=dict(_POOL_TAGS),
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    idp.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        MfaConfiguration="OPTIONAL",
        SoftwareTokenMfaConfiguration={"Enabled": True},
    )

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-mfa-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-behav-mfa-user-")
    password = "Sim2Real!Behav123"
    idp.admin_create_user(UserPoolId=pool_id, Username=username, TemporaryPassword=password, MessageAction="SUPPRESS")
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))

    # Before enrollment: plain password login succeeds with no challenge.
    pre_enroll = idp.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert "ChallengeName" not in pre_enroll, (
        f"an un-enrolled user was challenged before MFA was ever set up: {pre_enroll!r}"
    )
    access_token = pre_enroll["AuthenticationResult"]["AccessToken"]

    secret_code = idp.associate_software_token(AccessToken=access_token)["SecretCode"]
    used_code = _totp(secret_code)
    verify = idp.verify_software_token(AccessToken=access_token, UserCode=used_code)
    assert verify["Status"] == "SUCCESS", (
        f"the enrollment code derived from the issued secret was not accepted: {verify!r}"
    )
    idp.set_user_mfa_preference(
        AccessToken=access_token,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
    )

    # After enrollment + preference: a new login is challenged for the TOTP code.
    challenge = idp.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert challenge["ChallengeName"] == "SOFTWARE_TOKEN_MFA", (
        f"enrolling and preferring software-token MFA did not force a challenge on the next "
        f"login: {challenge!r}"
    )
    assert "AuthenticationResult" not in challenge, (
        f"tokens were issued before the MFA challenge was satisfied: {sorted(challenge)!r}"
    )
    session = challenge["Session"]

    # A wrong code is rejected outright -- login does not silently succeed.
    wrong_code = _totp(secret_code, for_time=time.time())
    wrong_code = "".join(str((int(d) + 1) % 10) for d in wrong_code)  # guaranteed mismatch
    wrong_code_response = _rejection_response(
        lambda: idp.respond_to_auth_challenge(
            ClientId=client_id,
            ChallengeName="SOFTWARE_TOKEN_MFA",
            Session=session,
            ChallengeResponses={"USERNAME": username, "SOFTWARE_TOKEN_MFA_CODE": wrong_code},
        )
    )
    wrong_code_error = wrong_code_response["Error"]["Code"]
    assert wrong_code_error == "CodeMismatchException", (
        f"a wrong TOTP code was not refused with the specific code: {wrong_code_error!r} "
        f"(full payload {wrong_code_response!r})"
    )
    wrong_code_message = wrong_code_response["Error"].get("Message", "")
    assert wrong_code_message == "Invalid code received for user", (
        f"expected the exact CodeMismatchException message 'Invalid code received for user', got {wrong_code_message!r}"
    )
    assert "AuthenticationResult" not in wrong_code_response, (
        f"tokens accompanied the refused MFA code: {sorted(wrong_code_response)!r}"
    )

    # The correct code completes sign-in and returns real tokens usable at an independent read.
    fresh_code = _wait_for_new_totp_code(secret_code, used_code)
    completed = idp.respond_to_auth_challenge(
        ClientId=client_id,
        ChallengeName="SOFTWARE_TOKEN_MFA",
        Session=session,
        ChallengeResponses={"USERNAME": username, "SOFTWARE_TOKEN_MFA_CODE": fresh_code},
    )
    new_access_token = completed.get("AuthenticationResult", {}).get("AccessToken")
    assert new_access_token, (
        f"the correct TOTP code did not complete sign-in, so the refusal above is not specific: "
        f"{completed!r}"
    )
    who = idp.get_user(AccessToken=new_access_token)
    assert who["Username"] == username, (
        f"the post-MFA access token is not usable against GetUser: {who!r}"
    )


def _totp(secret_b32: str, for_time: float | None = None, digits: int = 6, interval: int = 30) -> str:
    padded = secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(padded)
    counter = int((for_time if for_time is not None else time.time()) // interval)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


def _wait_for_new_totp_code(secret_b32: str, previous_code: str, timeout_s: float = 40.0) -> str:
    """Block until the TOTP window rolls over so a freshly minted code differs from
    previous_code -- Cognito rejects reusing the identical code across two calls."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        code = _totp(secret_b32)
        if code != previous_code:
            return code
        time.sleep(1.0)
    raise AssertionError("TOTP window never rolled over within timeout")


def _rejection_response(fn) -> dict:
    """Return the full botocore error response of a call expected to be REJECTED.

    Raises when the call SUCCEEDS instead of returning a falsy sentinel: an emulator accepting a
    code real AWS rejects is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, which is the defect: {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
