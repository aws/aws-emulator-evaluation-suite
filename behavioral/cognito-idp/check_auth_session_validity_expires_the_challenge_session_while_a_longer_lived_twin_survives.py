"""auth-session-validity-expires-the-challenge-session-while-a-longer-lived-twin-survives."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Cognito locks a user out after repeated wrong codes with NotAuthorizedException, the same code
# as an expired session, so expiry is probed at one floor and one ceiling point (5 wrong codes in
# total) and the expiry refusal is told apart from a lockout by its message.

CHECK = "auth-session-validity-expires-the-challenge-session-while-a-longer-lived-twin-survives"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]

PASSWORD = "Sup3r-Secret-Passw0rd!"
FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_SHORT_MINUTES = 3
_LONG_MINUTES = 15
#: Bracket around the short client's AuthSessionValidity boundary (180s), calibrated against a
#: measured expiry of ~180-188s, with margin on both sides so latency cannot flip a probe's side.
_FLOOR_S = 160.0
_CEILING_S = 300.0
_MSG_WRONG_CODE = "Invalid code received for user"
_MSG_SESSION_EXPIRED = "Invalid session for the user, session is expired."


# timing:real-time — ttl: 180 s https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPoolClient.html
@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A challenge session from an AuthSessionValidity=3 client is refused as expired after three
    minutes, while a same-age session from an AuthSessionValidity=15 twin client is still live.

    Reference: https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPoolClient.html
    """
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags=dict(_POOL_TAGS),
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _p=pool_id: c.delete_user_pool(UserPoolId=_p))
    # Enrolment needs MFA OPTIONAL: with the pool already ON an un-enrolled user is routed to
    # MFA_SETUP instead of a code challenge, so the pool is flipped to ON after enrolment.
    c.set_user_pool_mfa_config(
        UserPoolId=pool_id, MfaConfiguration="OPTIONAL",
        SoftwareTokenMfaConfiguration={"Enabled": True},
    )

    clients = {}
    for label, minutes in (("short", _SHORT_MINUTES), ("long", _LONG_MINUTES)):
        client_id = c.create_user_pool_client(
            UserPoolId=pool_id, ClientName=ctx.unique_name(f"sim2real-behav-cip-{label}-"),
            ExplicitAuthFlows=list(FLOWS), GenerateSecret=False, AuthSessionValidity=minutes,
        )["UserPoolClient"]["ClientId"]
        ctx.on_cleanup(
            lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
        )
        clients[label] = client_id
        described = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)[
            "UserPoolClient"
        ]
        assert described.get("AuthSessionValidity") == minutes, (
            f"the {label} client must report AuthSessionValidity={minutes}, DescribeUserPoolClient "
            f"says {described.get('AuthSessionValidity')!r}"
        )

    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(
        lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True
    )

    enrol_token = c.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=clients["short"], AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]["AccessToken"]
    secret = c.associate_software_token(AccessToken=enrol_token)["SecretCode"]
    verified = c.verify_software_token(
        AccessToken=enrol_token, UserCode=_totp(secret),
        FriendlyDeviceName="sim2real-behav-authenticator",
    )
    assert verified["Status"] == "SUCCESS", (
        f"the enrolment code derived from the issued secret was not accepted: {verified!r}"
    )
    c.admin_set_user_mfa_preference(
        UserPoolId=pool_id, Username=username,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
    )
    c.set_user_pool_mfa_config(
        UserPoolId=pool_id, MfaConfiguration="ON",
        SoftwareTokenMfaConfiguration={"Enabled": True},
    )

    def _open_session(label: str) -> str:
        init = c.admin_initiate_auth(
            UserPoolId=pool_id, ClientId=clients[label], AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
        )
        assert init.get("ChallengeName") == "SOFTWARE_TOKEN_MFA", (
            f"MFA ON must force the software-token challenge on the {label} client, got "
            f"{init.get('ChallengeName')!r}"
        )
        assert "AuthenticationResult" not in init, (
            f"tokens were issued before the MFA challenge was answered: {sorted(init)!r}"
        )
        return init["Session"]

    def _answer(label: str, session: str, code: str) -> dict:
        return c.admin_respond_to_auth_challenge(
            UserPoolId=pool_id, ClientId=clients[label], ChallengeName="SOFTWARE_TOKEN_MFA",
            Session=session,
            ChallengeResponses={"USERNAME": username, "SOFTWARE_TOKEN_MFA_CODE": code},
        )

    # --- t0: every session in this check is opened here, so all of them are the same age. Only
    # 3 per client are needed: t0 positive control, the floor/ceiling probe, and (for long) the
    # final completion — 5 wrong-code attempts total, well under the observed ~12-attempt lockout.
    opened_at = time.monotonic()
    short_sessions = {label: _open_session("short") for label in ("t0", "floor", "ceiling")}
    long_sessions = {label: _open_session("long") for label in ("t0", "twin", "final")}

    # --- positive control on both clients at t0: a wrong answer is refused for being WRONG,
    # which proves the session is live and being evaluated on both wirings.
    for label, sessions in (("short", short_sessions), ("long", long_sessions)):
        payload = _rejection_response(
            lambda _l=label, _s=sessions["t0"]: _answer(_l, _s, _a_different_code(secret))
        )
        assert payload["Error"]["Code"] == "CodeMismatchException", (
            f"at t0 the {label} client's session must be refused for the wrong CODE, not for the "
            f"session; got {payload['Error']['Code']!r} ({payload['Error'].get('Message')!r})"
        )
        assert payload["Error"].get("Message") == _MSG_WRONG_CODE, payload["Error"]

    # --- the floor: just under AuthSessionValidity=3's boundary, the short session must still be
    # live and refused for the ANSWER, proving it does not expire early.
    _sleep_until(opened_at, _FLOOR_S)
    floor_elapsed = time.monotonic() - opened_at
    floor_payload = _rejection_response(
        lambda: _answer("short", short_sessions["floor"], _a_different_code(secret))
    )
    assert floor_payload["Error"]["Code"] == "CodeMismatchException", (
        f"at {floor_elapsed:.0f}s (< {_SHORT_MINUTES * 60}s) the short client's session must "
        f"still be live and refused for the wrong code, got "
        f"{floor_payload['Error']['Code']!r} ({floor_payload['Error'].get('Message')!r}) — the "
        f"defect is expiring the session before AuthSessionValidity elapses"
    )
    assert floor_payload["Error"].get("Message") == _MSG_WRONG_CODE, floor_payload["Error"]

    # --- the ceiling, and the twin in the same instant: past AuthSessionValidity=3's boundary the
    # short session is refused for its SESSION, while the long client's same-age session — the
    # only difference being AuthSessionValidity=15 — is still refused for its ANSWER.
    _sleep_until(opened_at, _CEILING_S)
    ceiling_elapsed = time.monotonic() - opened_at
    ceiling_payload = _rejection_response(
        lambda: _answer("short", short_sessions["ceiling"], _a_different_code(secret))
    )
    assert ceiling_payload["Error"]["Code"] == "NotAuthorizedException", (
        f"at {ceiling_elapsed:.0f}s (> {_SHORT_MINUTES * 60}s) a challenge session from a client "
        f"with AuthSessionValidity={_SHORT_MINUTES} was still answerable "
        f"({ceiling_payload['Error']['Code']!r}), which is the over-permissive defect: the "
        f"session never expired"
    )
    ceiling_message = ceiling_payload["Error"].get("Message", "")
    assert ceiling_message == _MSG_SESSION_EXPIRED, (
        f"the refusal at {ceiling_elapsed:.0f}s is a NotAuthorizedException that does not name an "
        f"expired session, so it may be a different refusal (e.g. an attempt lockout): "
        f"{ceiling_message!r}"
    )

    twin_payload = _rejection_response(
        lambda: _answer("long", long_sessions["twin"], _a_different_code(secret))
    )
    assert twin_payload["Error"]["Code"] == "CodeMismatchException", (
        f"at {time.monotonic() - opened_at:.0f}s the AuthSessionValidity={_LONG_MINUTES} session "
        f"must still be live and refused for the wrong code, got "
        f"{twin_payload['Error']['Code']!r} ({twin_payload['Error'].get('Message')!r}) — the "
        f"target is expiring sessions on its own timer rather than on the client's setting"
    )
    assert twin_payload["Error"].get("Message") == _MSG_WRONG_CODE, twin_payload["Error"]

    # --- and that surviving wiring can still finish the sign-in: a correct code completes it and
    # the issued token is accepted by an independent read.
    done = _answer("long", long_sessions["final"], _totp(secret))
    result = done.get("AuthenticationResult", {})
    token = result.get("AccessToken")
    assert token, (
        f"a correct TOTP on the still-valid long session must complete the sign-in: {done!r}"
    )
    assert result.get("TokenType") == "Bearer" and result.get("RefreshToken"), (
        f"a completed sign-in must issue a full Bearer token set, not just an access token: "
        f"{sorted(result)!r}"
    )
    who = c.get_user(AccessToken=token)
    assert who["Username"] == username, (
        f"the post-challenge token must identify {username} at GetUser, got "
        f"{who.get('Username')!r}"
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
    now. Derived by walking candidates rather than hardcoding one, so a probe can never
    accidentally present the right answer."""
    nearby = {_totp(secret_b32, offset=o) for o in range(-4, 5)}
    for candidate in range(0, 1000000):
        text = str(candidate).zfill(6)
        if text not in nearby:
            return text
    raise AssertionError("no six-digit code outside the nearby TOTP window exists")


def _sleep_until(start: float, target_s: float) -> None:
    """Wait, in bounded chunks, until `target_s` has elapsed since `start`."""
    while True:
        remaining = target_s - (time.monotonic() - start)
        if remaining <= 0:
            return
        time.sleep(min(remaining, 30.0))


def _rejection_response(fn) -> dict:
    """Return the full botocore error response of a call expected to be REJECTED.
    Raises when the call SUCCEEDS, so an accepted wrong TOTP or expired session is never
    reported as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, which is the defect: {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
