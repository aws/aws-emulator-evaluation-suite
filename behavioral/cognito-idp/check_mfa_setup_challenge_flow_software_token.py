"""mfa-setup-challenge-flow-software-token."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "mfa-setup-challenge-flow-software-token"
GROUP = 'mfa-enforced-auth-flow'
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


def _totp_now(secret_b32: str, digits: int = 6, step: int = 30, offset: int = 0) -> str:
    """RFC 6238 TOTP code for a base32 secret; ``offset`` shifts the time-step
    counter to tolerate clock skew."""
    padded = secret_b32.upper()
    padded += "=" * ((8 - len(padded) % 8) % 8)
    key = base64.b32decode(padded)
    counter = int(time.time() // step) + offset
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[o : o + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """With MFA ON and nothing enrolled, the first login is challenged with MFA_SETUP, and
    AssociateSoftwareToken plus VerifySoftwareToken finish that sign-in for the user; the next login is
    challenged with SOFTWARE_TOKEN_MFA and completes for the same user."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags=_TAGS,
        Policies=_LENIENT_POLICY,
        AutoVerifiedAttributes=["email"],
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
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

    c.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="ON",
    )

    username = ctx.unique_name("sim2real-behav-cip-user-")
    password = "Str0ngPassw0rd!"
    c.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="Temp0rar1Pass!",
        MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}],
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )

    def _admin_auth():
        return c.admin_initiate_auth(
            UserPoolId=pool_id,
            ClientId=client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )

    first = _admin_auth()
    assert first.get("ChallengeName") == "MFA_SETUP", first.get("ChallengeName")
    setup_session = first["Session"]

    assoc = c.associate_software_token(Session=setup_session)
    secret = assoc["SecretCode"]
    assert secret, f"AssociateSoftwareToken returned no SecretCode: {assoc}"
    assoc_session = assoc["Session"]

    verify_status = None
    final_session = None
    last_error = None
    for offset in (0, -1, 1, -2, 2):
        try:
            resp = c.verify_software_token(
                Session=assoc_session,
                UserCode=_totp_now(secret, offset=offset),
                FriendlyDeviceName="probe-device",
            )
            verify_status = resp["Status"]
            final_session = resp["Session"]
            break
        except ClientError as exc:
            last_error = exc
            if exc.response["Error"]["Code"] != "CodeMismatchException":
                raise
            continue
    assert verify_status == "SUCCESS", (
        f"TOTP verification never succeeded during MFA setup, last_error={last_error}"
    )

    completed = c.admin_respond_to_auth_challenge(
        UserPoolId=pool_id,
        ClientId=client_id,
        ChallengeName="MFA_SETUP",
        Session=final_session,
        ChallengeResponses={"USERNAME": username},
    )
    access_token = completed["AuthenticationResult"]["AccessToken"]
    assert access_token, completed
    # Independent read at the destination: the token must actually identify
    # this user, not just be a non-empty string in the mutating call's own response.
    whoami = c.get_user(AccessToken=access_token)
    assert whoami["Username"] == username, (
        f"expected AccessToken from completed MFA_SETUP to identify {username}, "
        f"got {whoami['Username']}"
    )

    # The factor is now enrolled: a SUBSEQUENT login must challenge with
    # SOFTWARE_TOKEN_MFA, not re-demand MFA_SETUP.
    second = _admin_auth()
    assert second.get("ChallengeName") == "SOFTWARE_TOKEN_MFA", (
        f"expected SOFTWARE_TOKEN_MFA on a subsequent login now that a factor is "
        f"enrolled, got {second.get('ChallengeName')}"
    )

    mfa_completed = None
    last_error = None
    for offset in (0, -1, 1, -2, 2):
        try:
            mfa_completed = c.admin_respond_to_auth_challenge(
                UserPoolId=pool_id,
                ClientId=client_id,
                ChallengeName="SOFTWARE_TOKEN_MFA",
                Session=second["Session"],
                ChallengeResponses={
                    "USERNAME": username,
                    "SOFTWARE_TOKEN_MFA_CODE": _totp_now(secret, offset=offset),
                },
            )
            break
        except ClientError as exc:
            last_error = exc
            if exc.response["Error"]["Code"] != "CodeMismatchException":
                raise
            continue
    assert mfa_completed is not None, (
        f"expected the enrolled software token to complete the SOFTWARE_TOKEN_MFA "
        f"challenge, last_error={last_error}"
    )
    second_access_token = mfa_completed["AuthenticationResult"]["AccessToken"]
    assert second_access_token, mfa_completed
    # Independent read at the destination, again: prove the SUBSEQUENT sign-in's
    # token is real and usable, not merely present in the mutating response.
    second_whoami = c.get_user(AccessToken=second_access_token)
    assert second_whoami["Username"] == username, (
        f"expected AccessToken from completed SOFTWARE_TOKEN_MFA challenge to "
        f"identify {username}, got {second_whoami['Username']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
