"""user-srp-auth-wrong-password-and-unconfirmed-user-rejected."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "user-srp-auth-wrong-password-and-unconfirmed-user-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

PASSWORD = "Sup3r-Secret-Passw0rd!"
WRONG_PASSWORD = "Wr0ng-Secret-Passw0rd!"

SRP_FLOWS = ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]

_SRP_N = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
    16,
)

_SRP_G = 2


def _srp_bytes(x: int) -> bytes:
    """Two's-complement big-endian bytes matching Java BigInteger.toByteArray()
    for a non-negative value (leading 0x00 when the high bit is set)."""
    if x == 0:
        return b"\x00"
    b = x.to_bytes((x.bit_length() + 7) // 8, "big")
    return b"\x00" + b if b[0] & 0x80 else b


def _srp_sha256_int(*parts: bytes) -> int:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return int.from_bytes(h.digest(), "big")


def _srp_compute_x(pool_name: str, username: str, password: str, salt: int) -> int:
    inner = hashlib.sha256(
        pool_name.encode() + username.encode() + b":" + password.encode()
    ).digest()
    return _srp_sha256_int(_srp_bytes(salt), inner)


def _srp_caldera_hkdf(s: int, u: int) -> bytes:
    prk = hmac.new(_srp_bytes(u), _srp_bytes(s), hashlib.sha256).digest()
    okm = hmac.new(prk, b"Caldera Derived Key" + bytes([1]), hashlib.sha256).digest()
    return okm[:16]


def _cognito_srp_timestamp() -> str:
    """`EEE MMM d HH:mm:ss z yyyy` in US-locale/UTC, day NOT zero-padded — the
    exact format Cognito's SRP PASSWORD_CLAIM_SIGNATURE is computed over."""
    t = time.gmtime()
    return (
        f"{time.strftime('%a %b', t)} {t.tm_mday} "
        f"{time.strftime('%H:%M:%S', t)} UTC {t.tm_year}"
    )


def _srp_initiate(c, client_id: str, username: str) -> tuple:
    """USER_SRP_AUTH InitiateAuth; assert it returns the PASSWORD_VERIFIER challenge and
    return (a, big_a, response)."""
    a = secrets.randbits(256)
    big_a = pow(_SRP_G, a, _SRP_N)
    init = c.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_SRP_AUTH",
        AuthParameters={"USERNAME": username, "SRP_A": format(big_a, "x")},
    )
    assert init.get("ChallengeName") == "PASSWORD_VERIFIER", (
        f"expected PASSWORD_VERIFIER, got {init.get('ChallengeName')}"
    )
    return a, big_a, init


def _srp_respond(c, client_id: str, pool_name: str, password: str, a: int, big_a: int, init: dict):
    """Compute the PASSWORD_CLAIM_SIGNATURE from `password` (which may differ from the
    account's real password) against the server's own SRP_B/SALT/SECRET_BLOCK in `init`,
    and return RespondToAuthChallenge's response."""
    params = init["ChallengeParameters"]
    big_b = int(params["SRP_B"], 16)
    salt = int(params["SALT"], 16)
    secret_block_b64 = params["SECRET_BLOCK"]
    user_id_for_srp = params["USER_ID_FOR_SRP"]

    x = _srp_compute_x(pool_name, user_id_for_srp, password, salt)
    u = _srp_sha256_int(_srp_bytes(big_a), _srp_bytes(big_b))
    k = _srp_sha256_int(_srp_bytes(_SRP_N), _srp_bytes(_SRP_G))
    base = (big_b - k * pow(_SRP_G, x, _SRP_N)) % _SRP_N
    s = pow(base, a + u * x, _SRP_N)
    hkdf_key = _srp_caldera_hkdf(s, u)

    timestamp = _cognito_srp_timestamp()
    secret_block = base64.b64decode(secret_block_b64)
    signature = hmac.new(
        hkdf_key,
        pool_name.encode() + user_id_for_srp.encode() + secret_block + timestamp.encode(),
        hashlib.sha256,
    ).digest()

    respond_kwargs = dict(
        ClientId=client_id,
        ChallengeName="PASSWORD_VERIFIER",
        ChallengeResponses={
            "USERNAME": user_id_for_srp,
            "PASSWORD_CLAIM_SECRET_BLOCK": secret_block_b64,
            "TIMESTAMP": timestamp,
            "PASSWORD_CLAIM_SIGNATURE": base64.b64encode(signature).decode(),
        },
    )
    if init.get("Session"):
        respond_kwargs["Session"] = init["Session"]
    return c.respond_to_auth_challenge(**respond_kwargs)


def _srp_respond_to_auth_challenge(c, client_id: str, pool_name: str, username: str, password: str):
    """Run one full USER_SRP_AUTH round trip and return RespondToAuthChallenge's response."""
    a, big_a, init = _srp_initiate(c, client_id, username)
    return _srp_respond(c, client_id, pool_name, password, a, big_a, init)


def _assert_tokens(response: dict, what: str) -> None:
    result = response.get("AuthenticationResult") or {}
    for field in ("IdToken", "AccessToken", "RefreshToken"):
        assert result.get(field), f"expected {field} from {what}, got {response.keys()}"


def _rejection(fn) -> tuple:
    """Run fn and return the AWS (Error.Code, Error.Message) it raised. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """USER_SRP_AUTH with a PASSWORD_VERIFIER from the wrong password fails at RespondToAuthChallenge with
    NotAuthorizedException and leaves the user CONFIRMED, and an UNCONFIRMED user fails at InitiateAuth
    with UserNotConfirmedException, each with its exact message; once confirmed, the same flow works."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        DeletionProtection="INACTIVE",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=list(SRP_FLOWS),
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )
    pool_name = pool_id.split("_", 1)[1]

    confirmed_username = ctx.unique_name("sim2real-behav-cip-confirmed-")
    c.admin_create_user(UserPoolId=pool_id, Username=confirmed_username, MessageAction="SUPPRESS")
    ctx.on_cleanup(
        lambda _p=pool_id, _u=confirmed_username: c.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=confirmed_username, Password=PASSWORD, Permanent=True
    )
    status = c.admin_get_user(UserPoolId=pool_id, Username=confirmed_username)["UserStatus"]
    assert status == "CONFIRMED", f"expected CONFIRMED after a permanent password set, got {status}"

    # --- negative 1: a PASSWORD_VERIFIER computed from the wrong password ---
    wrong_code, wrong_message = _rejection(
        lambda: _srp_respond_to_auth_challenge(
            c, client_id, pool_name, confirmed_username, WRONG_PASSWORD
        )
    )
    assert wrong_code == "NotAuthorizedException", (
        f"USER_SRP_AUTH completed from the WRONG password must fail with "
        f"NotAuthorizedException, got {wrong_code}"
    )
    wrong_expected = "Incorrect username or password."
    assert wrong_message == wrong_expected, (
        f"expected message {wrong_expected!r}, got {wrong_message!r}"
    )

    # --- effect absent: the account is still usable, untouched by the failed attempt ---
    status_after = c.admin_get_user(UserPoolId=pool_id, Username=confirmed_username)["UserStatus"]
    assert status_after == "CONFIRMED", (
        f"a rejected SRP attempt must leave UserStatus at CONFIRMED, got {status_after}"
    )

    # --- negative 2: an UNCONFIRMED user completing SRP with its own real password ---
    unconfirmed_username = ctx.unique_name("sim2real-behav-cip-unconfirmed-")
    signup = c.sign_up(ClientId=client_id, Username=unconfirmed_username, Password=PASSWORD)
    ctx.on_cleanup(
        lambda _p=pool_id, _u=unconfirmed_username: c.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    assert signup["UserConfirmed"] is False, (
        f"expected UserConfirmed False right after SignUp, got {signup['UserConfirmed']}"
    )
    unconfirmed_status = c.admin_get_user(UserPoolId=pool_id, Username=unconfirmed_username)["UserStatus"]
    assert unconfirmed_status == "UNCONFIRMED", (
        f"expected UserStatus UNCONFIRMED after SignUp, got {unconfirmed_status}"
    )

    # The rejection comes at InitiateAuth itself: no PASSWORD_VERIFIER challenge is issued.
    unconfirmed_code, unconfirmed_message = _rejection(
        lambda: _srp_initiate(c, client_id, unconfirmed_username)
    )
    assert unconfirmed_code == "UserNotConfirmedException", (
        f"USER_SRP_AUTH for an UNCONFIRMED user, even with the correct password, must fail "
        f"with UserNotConfirmedException, got {unconfirmed_code}"
    )
    unconfirmed_expected = "User is not confirmed."
    assert unconfirmed_message == unconfirmed_expected, (
        f"expected message {unconfirmed_expected!r}, got {unconfirmed_message!r}"
    )

    # --- restore: once confirmed, the identical SRP flow with the same password returns tokens ---
    c.admin_confirm_sign_up(UserPoolId=pool_id, Username=unconfirmed_username)
    confirmed_now = c.admin_get_user(UserPoolId=pool_id, Username=unconfirmed_username)["UserStatus"]
    assert confirmed_now == "CONFIRMED", (
        f"expected UserStatus CONFIRMED after AdminConfirmSignUp, got {confirmed_now}"
    )
    restored = _srp_respond_to_auth_challenge(
        c, client_id, pool_name, unconfirmed_username, PASSWORD
    )
    _assert_tokens(restored, "SRP for the now-confirmed signed-up user")

    # --- positive control in the same file: the correct password on the CONFIRMED user works ---
    good = _srp_respond_to_auth_challenge(c, client_id, pool_name, confirmed_username, PASSWORD)
    _assert_tokens(good, "a correct SRP round-trip")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
