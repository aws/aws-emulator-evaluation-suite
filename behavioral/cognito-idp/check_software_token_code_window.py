"""software-token-code-window."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "software-token-code-window"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

PASSWORD = "Str0ngPassw0rd!"
FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]


def _totp_now(secret_b32, digits=6, step=30, offset=0):
    """RFC 6238 TOTP code for a base32 secret. `offset` shifts the time-step
    counter (in units of `step` seconds)."""
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


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """VerifySoftwareToken with a TOTP code about ten minutes outside the window fails with
    EnableSoftwareTokenMFAException and its exact message, and a current code from the same secret then
    succeeds, leaving SOFTWARE_TOKEN_MFA in GetUser's UserMFASettingList."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), AutoVerifiedAttributes=["email"], UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), ExplicitAuthFlows=list(FLOWS), GenerateSecret=False)["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))

    c.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, TemporaryPassword="Temp0rar1Pass!", MessageAction="SUPPRESS", UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}])
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True)

    access_token = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]["AccessToken"]

    secret = c.associate_software_token(AccessToken=access_token)["SecretCode"]
    assert secret, "AssociateSoftwareToken returned an empty SecretCode"

    stale_code, stale_message = _error(
        lambda: c.verify_software_token(AccessToken=access_token, UserCode=_totp_now(secret, offset=20))
    )
    assert stale_code == "EnableSoftwareTokenMFAException", (
        f"expected the stale TOTP code to be rejected with EnableSoftwareTokenMFAException, got {stale_code}"
    )
    expected_stale_message = "Code mismatch"
    assert stale_message == expected_stale_message, (
        f"expected message {expected_stale_message!r}, got {stale_message!r}"
    )

    verify_status = None
    for offset in (0, -1, 1, -2, 2):
        try:
            resp = c.verify_software_token(AccessToken=access_token, UserCode=_totp_now(secret, offset=offset))
        except Exception:
            continue
        if resp.get("Status") == "SUCCESS":
            verify_status = resp["Status"]
            break
    assert verify_status == "SUCCESS", "in-window TOTP verification never succeeded"

    # Terminal read: an independent GetUser call, not the mutating VerifySoftwareToken
    # response, is what proves the SAME secret's in-window code actually landed -- the
    # earlier stale attempt did not consume or invalidate it. Real Cognito's GetUser
    # omits UserMFASettingList entirely until a preference is set (the field is absent
    # after VerifySoftwareToken alone), so SetUserMFAPreference is
    # the operation that makes the effect observable through a different call than the
    # one that mutated.
    c.set_user_mfa_preference(
        AccessToken=access_token,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
    )
    after_success = c.get_user(AccessToken=access_token)
    assert "SOFTWARE_TOKEN_MFA" in (after_success.get("UserMFASettingList") or []), (
        f"in-window TOTP verification must enable software-token MFA, got {after_success.get('UserMFASettingList')}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
