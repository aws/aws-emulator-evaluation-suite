"""e2e-device-remembered-skips-mfa-challenge."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time

from behavioral_harness import tags

CHECK = "e2e-device-remembered-skips-mfa-challenge"
GROUP = "e2e"
SERVICES = ["cognito-idp"]

# ===== helpers =====
# SRP-6a over the RFC 5054 **3072-bit** group, plus the "Caldera Derived Key" HKDF Cognito
# documents at
# https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-device-tracking.html
# The group size is load-bearing: a 2048-bit N yields a verifier ConfirmDevice happily STORES
# (it never checks the algebra) and a claim the server then cannot reproduce -- failing every
# time as NotAuthorizedException: Incorrect username or password, indistinguishable from a
# wrong password.
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
_G = 2
_WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
_MONTHS = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
]


def _srp_bytes(x: int) -> bytes:
    """Two's-complement big-endian bytes matching Java BigInteger.toByteArray() for a
    non-negative value (a leading 0x00 when the high bit is set)."""
    if x == 0:
        return b"\x00"
    b = x.to_bytes((x.bit_length() + 7) // 8, "big")
    return b"\x00" + b if b[0] & 0x80 else b


def _srp_sha256_int(*parts: bytes) -> int:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return int.from_bytes(h.digest(), "big")


def _device_x(device_group_key: str, device_key: str, device_password: str, salt: int) -> int:
    """x = H(salt | H("<deviceGroupKey><deviceKey>:<devicePassword>"))."""
    inner = hashlib.sha256(
        device_group_key.encode() + device_key.encode() + b":" + device_password.encode()
    ).digest()
    return _srp_sha256_int(_srp_bytes(salt), inner)


def _device_secret_verifier_config(device_group_key: str, device_key: str, device_password: str) -> dict:
    """DeviceSecretVerifierConfig for ConfirmDevice: v = g^x mod N."""
    salt = int.from_bytes(os.urandom(16), "big")
    x_value = _device_x(device_group_key, device_key, device_password, salt)
    verifier = pow(_G, x_value, _SRP_N)
    return {
        "PasswordVerifier": base64.b64encode(_srp_bytes(verifier)).decode("utf-8"),
        "Salt": base64.b64encode(_srp_bytes(salt)).decode("utf-8"),
    }


def _device_srp_a() -> tuple[int, int]:
    small_a = int.from_bytes(os.urandom(32), "big")
    large_a = pow(_G, small_a, _SRP_N)
    return small_a, large_a


def _srp_timestamp() -> str:
    """Cognito's required form, `EEE MMM d HH:mm:ss z yyyy` in US-locale/UTC with the day NOT
    zero-padded. The weekday and month are tabled rather than taken from strftime's %a/%b, which
    would follow the host locale and silently produce a signature the server cannot reproduce."""
    now = time.gmtime()
    return (
        f"{_WEEKDAYS[now.tm_wday]} {_MONTHS[now.tm_mon - 1]} {now.tm_mday} "
        f"{now.tm_hour:02d}:{now.tm_min:02d}:{now.tm_sec:02d} UTC {now.tm_year}"
    )


def _caldera_hkdf(s: int, u: int) -> bytes:
    prk = hmac.new(_srp_bytes(u), _srp_bytes(s), hashlib.sha256).digest()
    return hmac.new(prk, b"Caldera Derived Key" + bytes([1]), hashlib.sha256).digest()[:16]


def _device_password_claim(
    device_group_key: str,
    device_key: str,
    device_password: str,
    username: str,
    small_a: int,
    large_a: int,
    srp_b_hex: str,
    salt_hex: str,
    secret_block_b64: str,
) -> dict:
    """The full DEVICE_PASSWORD_VERIFIER ChallengeResponses map, signed with the HKDF session
    key derived from the device password.

    `small_a`/`large_a` MUST be the same ephemeral pair whose A was sent in the preceding
    DEVICE_SRP_AUTH step -- u is H(A | B) and S is derived from a, so a freshly generated pair
    here would compute a session key the server cannot reproduce, and the resulting failure
    would look exactly like a wrong device password."""
    big_b = int(srp_b_hex, 16)
    salt = int(salt_hex, 16)
    u_value = _srp_sha256_int(_srp_bytes(large_a), _srp_bytes(big_b))
    if u_value == 0:
        raise ValueError("u cannot be zero")
    x_value = _device_x(device_group_key, device_key, device_password, salt)
    base = (
        big_b - _srp_sha256_int(_srp_bytes(_SRP_N), _srp_bytes(_G)) * pow(_G, x_value, _SRP_N)
    ) % _SRP_N
    s_value = pow(base, small_a + u_value * x_value, _SRP_N)
    hkdf = _caldera_hkdf(s_value, u_value)
    timestamp = _srp_timestamp()
    secret_block_bytes = base64.b64decode(secret_block_b64)
    msg = (
        device_group_key.encode("utf-8")
        + device_key.encode("utf-8")
        + secret_block_bytes
        + timestamp.encode("utf-8")
    )
    signature = hmac.new(hkdf, msg, hashlib.sha256).digest()
    return {
        "TIMESTAMP": timestamp,
        "USERNAME": username,
        "DEVICE_KEY": device_key,
        "PASSWORD_CLAIM_SECRET_BLOCK": secret_block_b64,
        "PASSWORD_CLAIM_SIGNATURE": base64.b64encode(signature).decode("utf-8"),
    }


def _totp_code(secret_b32: str, offset_steps: int = 0, step: int = 30, digits: int = 6) -> str:
    padded = secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(padded)
    counter = int(time.time() // step) + offset_steps
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


def _verify_software_token_with_retry(cognito, access_token: str, secret_code: str) -> None:
    last_exc = None
    for offset_steps in (0, -1, 1):
        try:
            resp = cognito.verify_software_token(
                AccessToken=access_token, UserCode=_totp_code(secret_code, offset_steps)
            )
            assert resp["Status"] == "SUCCESS"
            return
        except cognito.exceptions.CodeMismatchException as exc:  # pragma: no cover - clock skew
            last_exc = exc
    raise AssertionError(f"could not verify software token within +-1 step: {last_exc}")


def _wait_for_new_totp_code(secret_code: str, previous_code: str, timeout_s: float = 40.0) -> str:
    """Block until the 30s TOTP window rolls over so the next code differs from
    previous_code -- Cognito rejects reusing the identical code across two calls."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        code = _totp_code(secret_code)
        if code != previous_code:
            return code
        time.sleep(1.0)
    raise AssertionError("TOTP window never rolled over within timeout")


def _safe_delete_pool(cognito, pool_id: str) -> None:
    try:
        cognito.delete_user_pool(UserPoolId=pool_id)
    except cognito.exceptions.ResourceNotFoundException:
        pass


# ===== check body =====
@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A remembered device replaces the TOTP MFA challenge with a device SRP handshake that
    returns tokens, while the same user signing in without that device key is still challenged
    for a TOTP code."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
            }
        },
        DeviceConfiguration={
            "ChallengeRequiredOnNewDevice": True,
            "DeviceOnlyRememberedOnUserPrompt": True,
        },
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete_pool(cognito, pool_id))
    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real123"
    cognito.admin_create_user(
        UserPoolId=pool_id, Username=username, TemporaryPassword=password, MessageAction="SUPPRESS"
    )
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )

    # Bootstrap login: no MFA preference set yet, so this succeeds directly and yields an
    # access token used only to enroll TOTP. Real AWS does not treat the NewDeviceMetadata
    # minted here as MFA-skip-eligible -- that association is only made for a device born
    # out of *completing* a SOFTWARE_TOKEN_MFA challenge (verified empirically: marking this
    # bootstrap device "remembered" and re-presenting its DEVICE_KEY still drew a fresh
    # SOFTWARE_TOKEN_MFA challenge). So this device is discarded, and the device actually
    # registered below is minted from the MFA-challenge completion instead.
    bootstrap = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    bootstrap_access_token = bootstrap["AuthenticationResult"]["AccessToken"]

    # Turn on TOTP MFA for the user.
    secret_code = cognito.associate_software_token(AccessToken=bootstrap_access_token)["SecretCode"]
    enroll_code = _totp_code(secret_code)
    _verify_software_token_with_retry(cognito, bootstrap_access_token, secret_code)
    cognito.set_user_mfa_preference(
        AccessToken=bootstrap_access_token,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
    )

    # First login with MFA now enforced: challenged for the TOTP code, and completing that
    # challenge is what mints the NewDeviceMetadata this check will register and remember.
    challenge1 = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert challenge1.get("ChallengeName") == "SOFTWARE_TOKEN_MFA"
    # Cognito rejects reusing the exact same TOTP code across two calls, so wait for the
    # 30s window to roll over past the one already spent on enrollment.
    challenge1_code = _wait_for_new_totp_code(secret_code, enroll_code)
    completed1 = cognito.respond_to_auth_challenge(
        ClientId=client_id,
        ChallengeName="SOFTWARE_TOKEN_MFA",
        Session=challenge1["Session"],
        ChallengeResponses={"USERNAME": username, "SOFTWARE_TOKEN_MFA_CODE": challenge1_code},
    )
    access_token = completed1["AuthenticationResult"]["AccessToken"]
    new_device = completed1["AuthenticationResult"]["NewDeviceMetadata"]
    device_key = new_device["DeviceKey"]
    device_group_key = new_device["DeviceGroupKey"]

    # Register + remember the device using a real SRP secret verifier.
    device_password = base64.b64encode(os.urandom(40)).decode("utf-8")
    verifier_config = _device_secret_verifier_config(device_group_key, device_key, device_password)
    confirm = cognito.confirm_device(
        AccessToken=access_token,
        DeviceKey=device_key,
        DeviceName="sim2real-test-device",
        DeviceSecretVerifierConfig=verifier_config,
    )
    assert confirm["UserConfirmationNecessary"] is True
    cognito.update_device_status(
        AccessToken=access_token,
        DeviceKey=device_key,
        DeviceRememberedStatus="remembered",
    )
    # AdminGetDevice's DeviceAttributes doesn't surface the remembered-status flag back
    # (it's write-only via UpdateDeviceStatus), so the real proof is behavioral: the
    # subsequent auth attempt below skips the MFA challenge. Give the update a short
    # moment to take effect before that attempt (handled by its own bounded retry).

    # Control: a login from a device Cognito has never seen (no DEVICE_KEY) must still
    # be challenged for the TOTP code now that MFA is enforced for this user.
    unremembered = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert unremembered.get("ChallengeName") == "SOFTWARE_TOKEN_MFA"

    # The remembered device must not be challenged for SOFTWARE_TOKEN_MFA. Real AWS
    # either (a) replaces MFA with a DEVICE_SRP_AUTH/DEVICE_PASSWORD_VERIFIER handshake
    # that must be completed to get tokens, or (b) trusts the remembered device and
    # returns tokens directly. Either way, SOFTWARE_TOKEN_MFA must never appear. Allow a
    # short bounded retry: "remembered" status can take a moment to take effect on auth.
    remembered = None
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        remembered = cognito.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password, "DEVICE_KEY": device_key},
        )
        if remembered.get("ChallengeName") != "SOFTWARE_TOKEN_MFA":
            break
        time.sleep(3)
    assert remembered.get("ChallengeName") != "SOFTWARE_TOKEN_MFA", (
        "remembered device was still challenged for MFA"
    )

    if remembered.get("ChallengeName") is None:
        final = remembered
    else:
        assert remembered.get("ChallengeName") == "DEVICE_SRP_AUTH", (
            f"unexpected challenge for remembered device: {remembered.get('ChallengeName')}"
        )
        small_a, large_a = _device_srp_a()
        srp_resp = cognito.respond_to_auth_challenge(
            ClientId=client_id,
            ChallengeName="DEVICE_SRP_AUTH",
            ChallengeResponses={
                "USERNAME": username,
                "DEVICE_KEY": device_key,
                "SRP_A": format(large_a, "x"),
            },
            Session=remembered["Session"],
        )
        assert srp_resp.get("ChallengeName") == "DEVICE_PASSWORD_VERIFIER"
        params = srp_resp["ChallengeParameters"]
        claim = _device_password_claim(
            device_group_key,
            device_key,
            device_password,
            username,
            small_a,
            large_a,
            params["SRP_B"],
            params["SALT"],
            params["SECRET_BLOCK"],
        )
        # Real AWS does not echo a fresh Session on the DEVICE_PASSWORD_VERIFIER
        # ChallengeParameters (verified empirically: the response carries only
        # ChallengeName + ChallengeParameters, no Session key at all) -- the device-SRP
        # continuation reuses the Session minted by the original InitiateAuth call.
        final = cognito.respond_to_auth_challenge(
            ClientId=client_id,
            ChallengeName="DEVICE_PASSWORD_VERIFIER",
            ChallengeResponses=claim,
            Session=remembered["Session"],
        )

    assert final.get("ChallengeName") is None, "remembered device still hit another challenge"
    assert final["AuthenticationResult"]["AccessToken"], "device auth did not yield tokens"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
