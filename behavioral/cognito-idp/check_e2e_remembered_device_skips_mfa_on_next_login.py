"""e2e-remembered-device-skips-mfa-on-next-login."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time

from behavioral_harness import tags

CHECK = "e2e-remembered-device-skips-mfa-on-next-login"
GROUP = "e2e"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A confirmed device marked "remembered" skips SOFTWARE_TOKEN_MFA on the next login: the
    DEVICE_SRP_AUTH/DEVICE_PASSWORD_VERIFIER handshake yields tokens with no MFA challenge,
    while the same user signing in without the device key is still challenged for TOTP."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-device-pool-"),
        UserPoolTags={"sim2real:managed": "true"},
        DeviceConfiguration={
            "ChallengeRequiredOnNewDevice": True,
            "DeviceOnlyRememberedOnUserPrompt": True,
        },
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    idp.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        MfaConfiguration="OPTIONAL",
        SoftwareTokenMfaConfiguration={"Enabled": True},
    )

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-device-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-behav-device-user-")
    password = "Sim2Real!Behav123"
    idp.admin_create_user(UserPoolId=pool_id, Username=username, TemporaryPassword=password, MessageAction="SUPPRESS")
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))

    login0 = idp.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = login0["AuthenticationResult"]["AccessToken"]
    secret_code = idp.associate_software_token(AccessToken=access_token)["SecretCode"]
    enroll_code = _totp(secret_code)
    idp.verify_software_token(AccessToken=access_token, UserCode=enroll_code)
    idp.set_user_mfa_preference(
        AccessToken=access_token,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
    )

    # First login from a brand-new (unremembered) device: challenged for the TOTP code,
    # and NewDeviceMetadata is minted because no DEVICE_KEY was supplied.
    challenge1 = idp.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert challenge1["ChallengeName"] == "SOFTWARE_TOKEN_MFA", (
        f"a brand-new device should be challenged for TOTP MFA before any device is remembered: {challenge1!r}"
    )
    # Cognito rejects reusing the exact same TOTP code across two calls (replay
    # protection), so wait for the 30s window to roll over before minting the code
    # used to complete this challenge.
    challenge1_code = _wait_for_new_totp_code(secret_code, enroll_code)
    completed1 = idp.respond_to_auth_challenge(
        ClientId=client_id, ChallengeName="SOFTWARE_TOKEN_MFA", Session=challenge1["Session"],
        ChallengeResponses={"USERNAME": username, "SOFTWARE_TOKEN_MFA_CODE": challenge1_code},
    )
    new_device = completed1["AuthenticationResult"]["NewDeviceMetadata"]
    device_key = new_device["DeviceKey"]
    device_group_key = new_device["DeviceGroupKey"]
    device_access_token = completed1["AuthenticationResult"]["AccessToken"]

    device_secret = secrets.token_hex(32)
    salt_bytes, verifier_bytes = _device_verifier(device_group_key, device_key, device_secret)
    confirm = idp.confirm_device(
        AccessToken=device_access_token,
        DeviceKey=device_key,
        DeviceSecretVerifierConfig={
            "PasswordVerifier": base64.b64encode(verifier_bytes).decode(),
            "Salt": base64.b64encode(salt_bytes).decode(),
        },
        DeviceName=ctx.unique_name("sim2real-behav-device-"),
    )
    assert confirm["UserConfirmationNecessary"] is True, (
        f"DeviceOnlyRememberedOnUserPrompt=True must require a user prompt before trust: {confirm!r}"
    )
    idp.update_device_status(AccessToken=device_access_token, DeviceKey=device_key, DeviceRememberedStatus="remembered")
    ctx.on_cleanup(lambda: idp.forget_device(AccessToken=device_access_token, DeviceKey=device_key))

    # Second login WITH the remembered device key: no MFA challenge -- only a
    # DEVICE_SRP_AUTH/DEVICE_PASSWORD_VERIFIER handshake, completed below into real
    # tokens. "remembered" is eventually consistent on the auth path, so the routing is
    # polled for rather than assumed.
    login2 = None
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        login2 = idp.initiate_auth(
            ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password, "DEVICE_KEY": device_key},
        )
        if login2.get("ChallengeName") == "DEVICE_SRP_AUTH":
            break
        time.sleep(3.0)
    assert login2 is not None and login2.get("ChallengeName") == "DEVICE_SRP_AUTH", (
        f"the remembered device was not routed to DEVICE_SRP_AUTH within 60s: {login2!r}"
    )
    small_a, large_a = _srp_a()
    device_challenge = idp.respond_to_auth_challenge(
        ClientId=client_id, ChallengeName="DEVICE_SRP_AUTH", Session=login2["Session"],
        ChallengeResponses={"USERNAME": username, "DEVICE_KEY": device_key, "SRP_A": format(large_a, "x")},
    )
    assert device_challenge.get("ChallengeName") == "DEVICE_PASSWORD_VERIFIER", (
        f"the device SRP exchange did not reach the verifier challenge: {device_challenge!r}"
    )
    params = device_challenge["ChallengeParameters"]
    assert {"SRP_B", "SALT", "SECRET_BLOCK"} <= set(params), (
        f"the verifier challenge is missing SRP material to compute the claim from: {sorted(params)!r}"
    )
    claim = _device_password_claim(
        device_group_key, device_key, device_secret, username, small_a, large_a,
        params["SRP_B"], params["SALT"], params["SECRET_BLOCK"],
    )
    respond_kwargs = {
        "ClientId": client_id, "ChallengeName": "DEVICE_PASSWORD_VERIFIER", "ChallengeResponses": claim,
    }
    if device_challenge.get("Session"):
        respond_kwargs["Session"] = device_challenge["Session"]
    final = idp.respond_to_auth_challenge(**respond_kwargs)
    assert final.get("ChallengeName") is None, (
        f"the remembered device hit another challenge instead of completing: {final!r}"
    )
    assert final["AuthenticationResult"]["AccessToken"], (
        f"the device SRP round-trip issued no token: {final!r}"
    )

    # Control: the same user signing in WITHOUT the device key is still challenged for MFA,
    # proving the skip above was specific to the remembered device.
    challenge3 = idp.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert challenge3["ChallengeName"] == "SOFTWARE_TOKEN_MFA", (
        f"a login without the remembered device key must still be challenged for TOTP MFA: {challenge3!r}"
    )


# The "Caldera" SRP-6a variant Cognito uses for device auth, over the RFC 5054 3072-bit
# group -- NOT the 2048-bit group used for regular user SRP. Getting the group size wrong
# yields a verifier ConfirmDevice happily stores (it never checks the algebra) and a claim
# the server then cannot reproduce, failing as "NotAuthorizedException: Incorrect username
# or password" -- indistinguishable from a wrong password until measured against real AWS.
# See https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-device-tracking.html
_N_HEX = (
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
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
)
_BIG_N = int(_N_HEX, 16)
_G = 2
_INFO_BITS = b"Caldera Derived Key"
_WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def _srp_bytes(n: int) -> bytes:
    """Two's-complement big-endian bytes matching Java BigInteger.toByteArray() for a
    non-negative value (a leading 0x00 when the high bit is set) -- the padding Cognito's
    device-SRP hashes are computed over."""
    if n == 0:
        return b"\x00"
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x00" + b if b[0] & 0x80 else b


def _srp_sha256_int(*parts: bytes) -> int:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return int.from_bytes(h.digest(), "big")


def _compute_hkdf(ikm_bytes: bytes, salt_bytes: bytes) -> bytes:
    prk = hmac.new(salt_bytes, ikm_bytes, hashlib.sha256).digest()
    return hmac.new(prk, _INFO_BITS + b"\x01", hashlib.sha256).digest()[:16]


def _device_x(device_group_key: str, device_key: str, device_secret: str, salt: int) -> int:
    """x = H(salt | H("<deviceGroupKey><deviceKey>:<deviceSecret>"))."""
    inner = hashlib.sha256(
        device_group_key.encode() + device_key.encode() + b":" + device_secret.encode()
    ).digest()
    return _srp_sha256_int(_srp_bytes(salt), inner)


def _device_verifier(device_group_key: str, device_key: str, device_secret: str) -> tuple[bytes, bytes]:
    """Compute (salt_bytes, verifier_bytes) for ConfirmDevice's DeviceSecretVerifierConfig."""
    salt = int.from_bytes(secrets.token_bytes(16), "big")
    x = _device_x(device_group_key, device_key, device_secret, salt)
    v = pow(_G, x, _BIG_N)
    return _srp_bytes(salt), _srp_bytes(v)


def _srp_a() -> tuple[int, int]:
    small_a = int.from_bytes(secrets.token_bytes(128), "big") % _BIG_N
    large_a = pow(_G, small_a, _BIG_N)
    return small_a, large_a


def _srp_timestamp() -> str:
    """Cognito's required form, `EEE MMM d HH:mm:ss z yyyy` in US-locale/UTC with the day NOT
    zero-padded. The weekday and month are tabled rather than taken from strftime's %a/%b,
    which would follow the host locale and silently produce a signature the server cannot
    reproduce."""
    now = time.gmtime()
    return (
        f"{_WEEKDAYS[now.tm_wday]} {_MONTHS[now.tm_mon - 1]} {now.tm_mday} "
        f"{now.tm_hour:02d}:{now.tm_min:02d}:{now.tm_sec:02d} UTC {now.tm_year}"
    )


def _device_password_claim(
    device_group_key: str,
    device_key: str,
    device_secret: str,
    username: str,
    small_a: int,
    large_a: int,
    srp_b_hex: str,
    salt_hex: str,
    secret_block_b64: str,
) -> dict:
    """The full DEVICE_PASSWORD_VERIFIER ChallengeResponses map, signed with the HKDF
    session key derived from the device secret this device was ConfirmDevice'd with.

    `small_a`/`large_a` MUST be the same ephemeral pair whose A was sent in the preceding
    DEVICE_SRP_AUTH step -- u is H(A | B) and S is derived from a, so a freshly generated
    pair here would compute a session key the server cannot reproduce, and the resulting
    failure would look exactly like a wrong device secret."""
    big_b = int(srp_b_hex, 16)
    salt = int(salt_hex, 16)
    u = _srp_sha256_int(_srp_bytes(large_a), _srp_bytes(big_b))
    if u == 0:
        raise AssertionError("SRP u value must not be zero")
    x = _device_x(device_group_key, device_key, device_secret, salt)
    k = _srp_sha256_int(_srp_bytes(_BIG_N), _srp_bytes(_G))
    base = (big_b - k * pow(_G, x, _BIG_N)) % _BIG_N
    s_value = pow(base, small_a + u * x, _BIG_N)
    hkdf_key = _compute_hkdf(_srp_bytes(s_value), _srp_bytes(u))
    timestamp = _srp_timestamp()
    secret_block_bytes = base64.b64decode(secret_block_b64)
    msg = device_group_key.encode() + device_key.encode() + secret_block_bytes + timestamp.encode()
    signature = hmac.new(hkdf_key, msg, hashlib.sha256).digest()
    return {
        "TIMESTAMP": timestamp,
        "USERNAME": username,
        "DEVICE_KEY": device_key,
        "PASSWORD_CLAIM_SECRET_BLOCK": secret_block_b64,
        "PASSWORD_CLAIM_SIGNATURE": base64.b64encode(signature).decode(),
    }


def _totp(secret_b32: str, digits: int = 6, interval: int = 30) -> str:
    padded = secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(padded)
    counter = int(time.time() // interval)
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
