"""device-srp-auth-completes-with-a-locally-computed-device-verifier."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "device-srp-auth-completes-with-a-locally-computed-device-verifier"
GROUP = 'srp-auth'
SERVICES = ['cognito-idp']

PASSWORD = "Sim2Real-Device-Passw0rd!"
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A device registered with a locally derived SRP salt and verifier completes DEVICE_SRP_AUTH ->
    DEVICE_PASSWORD_VERIFIER and gets JWKS-verifiable tokens, while the same final step signed
    from a different device password is refused with NotAuthorizedException."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags=dict(_POOL_TAGS),
        DeviceConfiguration={"ChallengeRequiredOnNewDevice": True,
                             "DeviceOnlyRememberedOnUserPrompt": True},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _p=pool_id: c.delete_user_pool(UserPoolId=_p))
    c.set_user_pool_mfa_config(
        UserPoolId=pool_id, MfaConfiguration="OPTIONAL",
        SoftwareTokenMfaConfiguration={"Enabled": True},
    )

    client_id = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )

    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS",
                        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}])
    ctx.on_cleanup(
        lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD,
                              Permanent=True)

    # Enrol TOTP so the pool issues NewDeviceMetadata off a completed MFA challenge -- the
    # sequence that reliably routes a later remembered-device sign-in to DEVICE_SRP_AUTH.
    setup = c.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]["AccessToken"]
    secret = c.associate_software_token(AccessToken=setup)["SecretCode"]
    enrol_code = _totp(secret)
    verify = c.verify_software_token(AccessToken=setup, UserCode=enrol_code,
                                    FriendlyDeviceName="sim2real-behav-authenticator")
    assert verify["Status"] == "SUCCESS", (
        f"the enrolment code derived from the issued secret was not accepted: {verify!r}"
    )
    c.set_user_mfa_preference(
        AccessToken=setup, SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True}
    )

    challenge = c.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )
    assert challenge["ChallengeName"] == "SOFTWARE_TOKEN_MFA", (
        f"the un-tracked device was not challenged for MFA: {challenge!r}"
    )
    solved = c.respond_to_auth_challenge(
        ClientId=client_id, ChallengeName="SOFTWARE_TOKEN_MFA", Session=challenge["Session"],
        ChallengeResponses={"USERNAME": username,
                            "SOFTWARE_TOKEN_MFA_CODE": _wait_for_new_totp_code(secret,
                                                                              enrol_code)},
    )["AuthenticationResult"]
    device_key = solved["NewDeviceMetadata"]["DeviceKey"]
    device_group_key = solved["NewDeviceMetadata"]["DeviceGroupKey"]
    device_token = solved["AccessToken"]

    # ConfirmDevice is not a bare "remember this key": Cognito rejects it outright unless the
    # SRP verifier is well formed, so acceptance here is already a crypto round trip.
    device_password = base64.standard_b64encode(os.urandom(40)).decode()
    salt, verifier = _device_verifier(device_group_key, device_key, device_password)
    confirmed = c.confirm_device(
        AccessToken=device_token, DeviceKey=device_key,
        DeviceName=ctx.unique_name("sim2real-behav-cip-dev-"),
        DeviceSecretVerifierConfig={
            "PasswordVerifier": base64.b64encode(_srp_bytes(verifier)).decode(),
            "Salt": base64.b64encode(_srp_bytes(salt)).decode(),
        },
    )
    ctx.on_cleanup(
        lambda _t=device_token, _k=device_key: c.forget_device(AccessToken=_t, DeviceKey=_k)
    )
    assert confirmed["UserConfirmationNecessary"] is True, (
        f"DeviceOnlyRememberedOnUserPrompt=True must require a user prompt: {confirmed!r}"
    )
    c.update_device_status(AccessToken=device_token, DeviceKey=device_key,
                          DeviceRememberedStatus="remembered")

    # --- positive: complete the exchange with the password the verifier was derived from ---
    verifier_challenge, small_a, large_a = _reach_device_password_verifier(
        c, client_id, username, device_key)
    params = verifier_challenge["ChallengeParameters"]
    good = _answer_verifier(
        c, client_id, verifier_challenge,
        _device_password_claim(
            device_group_key, device_key, device_password, username, small_a, large_a,
            params["SRP_B"], params["SALT"], params["SECRET_BLOCK"],
        ),
    )
    assert good.get("ChallengeName") is None, (
        f"the completed device exchange hit a further challenge: {good!r}"
    )
    token = good.get("AuthenticationResult", {}).get("AccessToken")
    assert token, f"the device SRP round-trip issued no token: {good!r}"
    claims = _verify_jwt_against_jwks(c, pool_id, token)
    assert claims["username"] == username, (
        f"the device-SRP access token names the wrong user: {claims!r}"
    )
    assert claims.get("device_key") == device_key, (
        f"the device-SRP access token does not carry the device it was issued to: "
        f"{claims.get('device_key')!r} != {device_key!r}"
    )

    # --- the one broken thing: the SAME claim signed from a different device password ---
    wrong_password = base64.standard_b64encode(os.urandom(40)).decode()
    assert wrong_password != device_password, "the two device passwords must differ"
    wrong_challenge, wrong_small_a, wrong_large_a = _reach_device_password_verifier(
        c, client_id, username, device_key)
    wrong_params = wrong_challenge["ChallengeParameters"]
    error_payload = _rejection_response(
        lambda: _answer_verifier(
            c, client_id, wrong_challenge,
            _device_password_claim(
                device_group_key, device_key, wrong_password, username,
                wrong_small_a, wrong_large_a,
                wrong_params["SRP_B"], wrong_params["SALT"], wrong_params["SECRET_BLOCK"],
            ),
        )
    )
    code = error_payload["Error"]["Code"]
    assert code == "NotAuthorizedException", (
        f"a device claim derived from the wrong password was not refused with the exact code: "
        f"{code!r} (full payload {error_payload!r})"
    )
    message = error_payload["Error"].get("Message", "")
    assert message == "Incorrect username or password.", (
        f"expected the exact NotAuthorizedException message 'Incorrect username or password.', got {message!r}"
    )
    assert "AuthenticationResult" not in error_payload, (
        f"tokens accompanied the refused device claim: {sorted(error_payload)!r}"
    )


# ===== helpers =====
# The "Caldera" SRP-6a variant Cognito uses, over the RFC 5054 **3072-bit** group. The group size
# is load-bearing: a 2048-bit N yields a verifier ConfirmDevice happily STORES (it never checks
# the algebra) and a claim the server then cannot reproduce -- failing as
# "NotAuthorizedException: Incorrect username or password", indistinguishable from a wrong
# password. Device auth hashes deviceGroupKey+deviceKey where user SRP hashes poolName+username.
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
_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


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


def _device_verifier(device_group_key: str, device_key: str, device_password: str):
    """(salt_int, verifier_int) for ConfirmDevice's DeviceSecretVerifierConfig: v = g^x mod N."""
    salt = int.from_bytes(os.urandom(16), "big")
    x_value = _device_x(device_group_key, device_key, device_password, salt)
    return salt, pow(_G, x_value, _SRP_N)


def _srp_timestamp() -> str:
    """Cognito's required form, `EEE MMM d HH:mm:ss z yyyy` in US-locale/UTC with the day NOT
    zero-padded. The weekday and month are tabled rather than taken from strftime's %a/%b, which
    would follow the host locale and silently produce a signature the server cannot reproduce."""
    now = time.gmtime()
    return (f"{_WEEKDAYS[now.tm_wday]} {_MONTHS[now.tm_mon - 1]} {now.tm_mday} "
            f"{now.tm_hour:02d}:{now.tm_min:02d}:{now.tm_sec:02d} UTC {now.tm_year}")


def _caldera_hkdf(s: int, u: int) -> bytes:
    prk = hmac.new(_srp_bytes(u), _srp_bytes(s), hashlib.sha256).digest()
    return hmac.new(prk, b"Caldera Derived Key" + bytes([1]), hashlib.sha256).digest()[:16]


def _device_password_claim(device_group_key, device_key, device_password, username,
                           small_a, large_a, srp_b_hex, salt_hex, secret_block_b64) -> dict:
    """The full DEVICE_PASSWORD_VERIFIER ChallengeResponses map, signed with the HKDF session
    key derived from the device password.

    `small_a`/`large_a` MUST be the same ephemeral pair whose A was sent in the preceding
    DEVICE_SRP_AUTH step -- u is H(A | B) and S is derived from a, so a freshly generated pair
    here would compute a session key the server cannot reproduce, and the resulting failure
    would look exactly like a wrong device password."""
    big_b = int(srp_b_hex, 16)
    salt = int(salt_hex, 16)
    u_value = _srp_sha256_int(_srp_bytes(large_a), _srp_bytes(big_b))
    assert u_value != 0, "the SRP u value must not be zero"
    x_value = _device_x(device_group_key, device_key, device_password, salt)
    base = (big_b - _srp_sha256_int(_srp_bytes(_SRP_N), _srp_bytes(_G))
            * pow(_G, x_value, _SRP_N)) % _SRP_N
    s_value = pow(base, small_a + u_value * x_value, _SRP_N)
    hkdf = _caldera_hkdf(s_value, u_value)
    timestamp = _srp_timestamp()
    msg = (device_group_key.encode() + device_key.encode()
           + base64.b64decode(secret_block_b64) + timestamp.encode())
    return {
        "TIMESTAMP": timestamp,
        "USERNAME": username,
        "DEVICE_KEY": device_key,
        "PASSWORD_CLAIM_SECRET_BLOCK": secret_block_b64,
        "PASSWORD_CLAIM_SIGNATURE": base64.b64encode(
            hmac.new(hkdf, msg, hashlib.sha256).digest()).decode(),
    }


def _reach_device_password_verifier(c, client_id, username, device_key):
    """Drive a fresh sign-in from the remembered device up to DEVICE_PASSWORD_VERIFIER.

    Returns (challenge_response, small_a, large_a) -- the ephemeral pair is returned rather than
    discarded because the claim in the NEXT step must be computed from the same one.

    The remembered status is eventually consistent on the auth path, so the DEVICE_SRP_AUTH
    routing is polled for rather than assumed -- the assertion is that it arrives, never that
    an MFA challenge is acceptable instead."""
    deadline = time.monotonic() + 60
    login = None
    while time.monotonic() < deadline:
        login = c.initiate_auth(
            ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD,
                            "DEVICE_KEY": device_key},
        )
        if login.get("ChallengeName") == "DEVICE_SRP_AUTH":
            break
        time.sleep(3.0)
    assert login is not None and login.get("ChallengeName") == "DEVICE_SRP_AUTH", (
        f"the remembered device was not routed to DEVICE_SRP_AUTH: {login!r}"
    )
    small_a = int.from_bytes(os.urandom(32), "big")
    large_a = pow(_G, small_a, _SRP_N)
    srp = c.respond_to_auth_challenge(
        ClientId=client_id, ChallengeName="DEVICE_SRP_AUTH", Session=login["Session"],
        ChallengeResponses={"USERNAME": username, "DEVICE_KEY": device_key,
                            "SRP_A": format(large_a, "x")},
    )
    assert srp.get("ChallengeName") == "DEVICE_PASSWORD_VERIFIER", (
        f"the device SRP exchange did not reach the verifier challenge: {srp!r}"
    )
    assert {"SRP_B", "SALT", "SECRET_BLOCK"} <= set(srp["ChallengeParameters"]), (
        f"the verifier challenge is missing the SRP material the claim is computed from: "
        f"{sorted(srp['ChallengeParameters'])!r}"
    )
    return srp, small_a, large_a


def _answer_verifier(c, client_id, challenge, responses):
    """Answer DEVICE_PASSWORD_VERIFIER.

    On real AWS the DEVICE_SRP_AUTH response carries only
    ['ChallengeName', 'ChallengeParameters'] -- there is **no `Session`** to continue, because the
    server's state travels in SECRET_BLOCK, which the claim signs. So Session is forwarded only
    when the service supplies one, rather than being required."""
    kwargs = {"ClientId": client_id, "ChallengeName": "DEVICE_PASSWORD_VERIFIER",
              "ChallengeResponses": responses}
    if challenge.get("Session"):
        kwargs["Session"] = challenge["Session"]
    return c.respond_to_auth_challenge(**kwargs)


def _rejection_response(fn) -> dict:
    """Return the full botocore error response of a call expected to be REJECTED.

    Raises when the call SUCCEEDS instead of returning a falsy sentinel: a target accepting a
    claim real AWS rejects must never be reported as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, which is the defect: {result!r}"
    )


def _decode_jwt_segment(segment: str) -> dict:
    """base64url-decode a JWT header/payload segment into a dict (no signature verify)."""
    import json
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding))


def _verify_rs256(signing_input: bytes, signature: bytes, jwk: dict) -> bool:
    """Verify an RS256 (RSASSA-PKCS1-v1_5, SHA-256) JWT signature against a JWK public key."""
    def _to_int(seg):
        return int.from_bytes(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)), "big")
    n, e = _to_int(jwk["n"]), _to_int(jwk["e"])
    k = (n.bit_length() + 7) // 8
    em = pow(int.from_bytes(signature, "big"), e, n).to_bytes(k, "big")
    digest = hashlib.sha256(signing_input).digest()
    prefix = bytes.fromhex("3031300d060960864801650304020105000420")  # SHA-256 DigestInfo DER
    ps_len = k - len(prefix) - len(digest) - 3
    return em == b"\x00\x01" + b"\xff" * ps_len + b"\x00" + prefix + digest


def _verify_jwt_against_jwks(client, pool_id: str, token: str) -> dict:
    """Fetch the pool's published JWKS, verify token's RS256 signature, return its claims."""
    import json
    header_b64, payload_b64, sig_b64 = token.split(".")
    kid = _decode_jwt_segment(header_b64).get("kid")
    url = f"{client.meta.endpoint_url.rstrip('/')}/{pool_id}/.well-known/jwks.json"
    with urllib.request.urlopen(url, timeout=30) as r:  # noqa: S310 - fixed scheme from the client
        jwks = json.loads(r.read().decode())
    jwk = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    assert jwk is not None, f"kid {kid!r} is absent from the pool JWKS {jwks!r}"
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
    assert _verify_rs256(signing_input, signature, jwk) is True, (
        f"the device-SRP access token does not verify against the pool JWKS key {kid!r}"
    )
    return _decode_jwt_segment(payload_b64)


def _totp(secret_b32: str, digits: int = 6, step: int = 30) -> str:
    """RFC 6238 TOTP over a base32 secret."""
    padded = secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(padded)
    digest = hmac.new(key, struct.pack(">Q", int(time.time() // step)), hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code_int).zfill(digits)


def _wait_for_new_totp_code(secret_b32: str, previous_code: str, timeout_s: float = 45.0) -> str:
    """Poll the derived code until the 30 s step rolls it over: Cognito refuses a code it has
    already consumed, so the challenge cannot replay the enrolment code."""
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
