"""enable-software-token-mfa-precondition-error."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "enable-software-token-mfa-precondition-error"
GROUP = 'overly-permissive'
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
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises, so an
    emulator accepting a call real AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _admin_auth(c, pool_id, client_id, username, password):
    return c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )


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


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """In MFA_SETUP, VerifySoftwareToken before AssociateSoftwareToken fails with NotAuthorizedException
    and a wrong code with EnableSoftwareTokenMFAException, each with its exact message and the login
    still at MFA_SETUP; the correct code completes setup and later logins get SOFTWARE_TOKEN_MFA."""
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

    challenge = _admin_auth(c, pool_id, client_id, username, password)
    assert challenge.get("ChallengeName") == "MFA_SETUP", challenge.get("ChallengeName")

    # No AssociateSoftwareToken call has happened yet for this session.
    code0 = _error(
        lambda: c.verify_software_token(Session=challenge["Session"], UserCode="123456")
    )
    assert code0 == ("NotAuthorizedException", "Invalid session for the user."), (
        f"expected NotAuthorizedException verifying a software token before "
        f"AssociateSoftwareToken was ever called for this session, got {code0}"
    )
    # Effect absent: a fresh, independent AdminInitiateAuth (not VerifySoftwareToken's
    # own response) shows the rejected call enrolled nothing -- the NEXT login attempt
    # is still challenged with MFA_SETUP, not SOFTWARE_TOKEN_MFA.
    probe1 = _admin_auth(c, pool_id, client_id, username, password)
    assert probe1.get("ChallengeName") == "MFA_SETUP", (
        f"a rejected VerifySoftwareToken(Session=...) with no prior AssociateSoftwareToken "
        f"must not enroll any MFA factor, but a fresh login now sees "
        f"{probe1.get('ChallengeName')!r} instead of MFA_SETUP"
    )

    assoc = c.associate_software_token(Session=challenge["Session"])
    secret = assoc["SecretCode"]
    assoc_session = assoc["Session"]

    # Now the session has an associated (but not yet verified) secret --
    # submitting a WRONG code is a distinct precondition failure specific to
    # software-token MFA configuration.
    code1 = _error(
        lambda: c.verify_software_token(Session=assoc_session, UserCode="000000")
    )
    assert code1 == ("EnableSoftwareTokenMFAException", "Code mismatch"), (
        f"expected EnableSoftwareTokenMFAException submitting a wrong code while "
        f"configuring software token MFA during MFA_SETUP, got {code1}"
    )
    # Effect absent again, on the same independent probe: AssociateSoftwareToken alone
    # (without a correctly-verified code) must not have enrolled the factor either.
    probe2 = _admin_auth(c, pool_id, client_id, username, password)
    assert probe2.get("ChallengeName") == "MFA_SETUP", (
        f"a wrong TOTP code during MFA_SETUP must not enroll software-token MFA despite "
        f"AssociateSoftwareToken having been called, but a fresh login now sees "
        f"{probe2.get('ChallengeName')!r} instead of MFA_SETUP"
    )

    # Sanity: the normal Associate -> Verify(correct code) sequence for the
    # SAME session still works.
    verified = None
    for offset in (0, -1, 1, -2, 2):
        try:
            resp = c.verify_software_token(
                Session=assoc_session, UserCode=_totp_now(secret, offset=offset)
            )
            verified = resp
            break
        except Exception:
            continue
    assert verified is not None and verified.get("Status") == "SUCCESS", (
        "expected the properly-associated software token to verify successfully "
        "once actually associated"
    )

    # Terminal read: complete the challenge (RespondToAuthChallenge, a different
    # operation than VerifySoftwareToken), then probe with a THIRD independent
    # AdminInitiateAuth -- the destination-side consequence of a real enrollment is
    # that the state machine has advanced: it now challenges with SOFTWARE_TOKEN_MFA
    # instead of re-demanding MFA_SETUP.
    completed = c.admin_respond_to_auth_challenge(
        UserPoolId=pool_id,
        ClientId=client_id,
        ChallengeName="MFA_SETUP",
        Session=verified["Session"],
        ChallengeResponses={"USERNAME": username},
    )
    assert completed.get("AuthenticationResult", {}).get("AccessToken"), (
        f"expected the completed MFA_SETUP challenge to hand back tokens, got {completed}"
    )
    probe3 = _admin_auth(c, pool_id, client_id, username, password)
    assert probe3.get("ChallengeName") == "SOFTWARE_TOKEN_MFA", (
        f"expected a subsequent login to challenge with SOFTWARE_TOKEN_MFA now that the "
        f"factor is actually enrolled, got {probe3.get('ChallengeName')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
