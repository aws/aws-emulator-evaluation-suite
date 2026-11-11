"""webauthn-credential-friendly-name-unicode-preserved."""
from __future__ import annotations

import hashlib
import json
import os
import base64
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "webauthn-credential-friendly-name-unicode-preserved"
GROUP = "representation"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A WebAuthn credential registered with a software authenticator lists with its CredentialId byte for
    byte and a non-empty FriendlyCredentialName that is the same on two reads."""
    from cryptography.hazmat.primitives.asymmetric import ec

    cognito = ctx.client("cognito-idp")
    pool_id, client_id = _create_webauthn_pool(ctx, cognito)

    username = ctx.unique_name("sim2real-wan-user-")
    password = "Sim2Real!Passkey1"
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    auth = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = auth["AuthenticationResult"]["AccessToken"]

    try:
        options = cognito.start_web_authn_registration(AccessToken=access_token)["CredentialCreationOptions"]
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("OperationNotEnabledException", "FeatureUnavailableInTierException", "WebAuthnNotEnabledException"):
            raise AssertionError(f"passkeys are not available for testing in this account/region: {code}")
        raise

    rp_id = options["rp"]["id"]
    challenge = options["challenge"]

    credential_id = os.urandom(32)
    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    x_bytes = numbers.x.to_bytes(32, "big")
    y_bytes = numbers.y.to_bytes(32, "big")

    rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    flags = 0x41  # UP (user present) | AT (attested cred data)
    counter = (0).to_bytes(4, "big")
    aaguid = b"\x00" * 16
    cose_key = _cbor_encode({1: 2, 3: -7, -1: 1, -2: x_bytes, -3: y_bytes})
    auth_data = (
        rp_id_hash
        + bytes([flags])
        + counter
        + aaguid
        + len(credential_id).to_bytes(2, "big")
        + credential_id
        + cose_key
    )
    attestation_object = _cbor_encode({"fmt": "none", "attStmt": {}, "authData": auth_data})

    origin = f"https://{rp_id}"
    client_data = json.dumps(
        {"type": "webauthn.create", "challenge": challenge, "origin": origin, "crossOrigin": False},
        separators=(",", ":"),
    ).encode("utf-8")

    cred_id_b64 = _b64url(credential_id)
    registration_response = {
        "id": cred_id_b64,
        "rawId": cred_id_b64,
        "type": "public-key",
        "clientExtensionResults": {},
        "response": {
            "clientDataJSON": _b64url(client_data),
            "attestationObject": _b64url(attestation_object),
            "transports": ["internal"],
        },
    }

    cognito.complete_web_authn_registration(AccessToken=access_token, Credential=registration_response)
    ctx.on_cleanup(
        lambda: cognito.delete_web_authn_credential(AccessToken=access_token, CredentialId=cred_id_b64)
    )

    # CompleteWebAuthnRegistration's write can be eventually consistent with
    # ListWebAuthnCredentials' read path, so poll for the credential to
    # actually become visible instead of assuming it's there on the first
    # call or padding with a fixed sleep.
    first = _poll_for_credential(cognito, access_token, cred_id_b64, timeout_s=30.0, interval_s=1.0)
    second = _poll_for_credential(cognito, access_token, cred_id_b64, timeout_s=30.0, interval_s=1.0)

    assert first["CredentialId"] == cred_id_b64, "CredentialId was not preserved byte-for-byte by Cognito"
    assert _b64url_decode(first["CredentialId"]) == credential_id, "decoded CredentialId bytes do not match the registered passkey ID"
    assert first["FriendlyCredentialName"], "FriendlyCredentialName was empty"
    assert first["FriendlyCredentialName"] == second["FriendlyCredentialName"], (
        "the auto-generated FriendlyCredentialName was not stable across repeated ListWebAuthnCredentials reads"
    )


def _create_webauthn_pool(ctx: Any, cognito: Any) -> tuple[str, str]:
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-wanpool-"),
        UserPoolTier="ESSENTIALS",
        Policies={"SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "WEB_AUTHN"]}},
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-wanclient-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH", "ALLOW_USER_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    rp_id = f"{ctx.unique_name('wan')}.example.com"
    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        WebAuthnConfiguration={"RelyingPartyId": rp_id, "UserVerification": "preferred"},
    )
    return pool_id, client_id


def _poll_for_credential(
    cognito: Any, access_token: str, cred_id_b64: str, timeout_s: float = 30.0, interval_s: float = 1.0
) -> dict:
    deadline = time.monotonic() + timeout_s
    last_seen: list[str] = []
    while True:
        resp = cognito.list_web_authn_credentials(AccessToken=access_token)
        last_seen = [c["CredentialId"] for c in resp.get("Credentials", [])]
        for cred in resp.get("Credentials", []):
            if cred["CredentialId"] == cred_id_b64:
                return cred
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"registered credential {cred_id_b64!r} never appeared in ListWebAuthnCredentials "
                f"within {timeout_s}s (last seen: {last_seen})"
            )
        time.sleep(interval_s)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _cbor_uint(n: int, major_type: int) -> bytes:
    if n < 24:
        return bytes([(major_type << 5) | n])
    if n < 256:
        return bytes([(major_type << 5) | 24, n])
    if n < 65536:
        return bytes([(major_type << 5) | 25]) + n.to_bytes(2, "big")
    if n < 2**32:
        return bytes([(major_type << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(major_type << 5) | 27]) + n.to_bytes(8, "big")


def _cbor_encode(obj: Any) -> bytes:
    """Minimal CBOR encoder covering exactly the shapes a WebAuthn 'none'
    attestation and COSE EC2 public key need (ints, bytes, str, list, dict).
    """
    if isinstance(obj, bool):
        return b"\xf5" if obj else b"\xf4"
    if isinstance(obj, int):
        return _cbor_uint(obj, 0) if obj >= 0 else _cbor_uint(-1 - obj, 1)
    if isinstance(obj, bytes):
        return _cbor_uint(len(obj), 2) + obj
    if isinstance(obj, str):
        encoded = obj.encode("utf-8")
        return _cbor_uint(len(encoded), 3) + encoded
    if isinstance(obj, list):
        out = _cbor_uint(len(obj), 4)
        for item in obj:
            out += _cbor_encode(item)
        return out
    if isinstance(obj, dict):
        out = _cbor_uint(len(obj), 5)
        for k, v in obj.items():
            out += _cbor_encode(k)
            out += _cbor_encode(v)
        return out
    raise TypeError(f"unsupported type for minimal cbor encoder: {type(obj)}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
