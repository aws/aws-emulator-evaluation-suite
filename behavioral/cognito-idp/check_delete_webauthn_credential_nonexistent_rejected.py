"""delete-webauthn-credential-nonexistent-rejected."""
from __future__ import annotations

import base64
import hashlib
import json
import os

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-webauthn-credential-nonexistent-rejected"
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
_RELYING_PARTY_ID = "example.com"
# NIST P-256 base-point coordinates as the simulated authenticator's public key: attestation
# format "none" carries no signature, so a fixed valid curve point suffices without extra libraries.
_P256_GX = bytes.fromhex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
_P256_GY = bytes.fromhex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteWebAuthnCredential for a never-registered CredentialId answers
    ResourceNotFoundException "The credential does not exist" and leaves the user's passkey, while
    deleting the registered passkey removes it and a repeat delete answers the same error."""
    c = ctx.client("cognito-idp")

    # ESSENTIALS-tier pool with WEB_AUTHN allowed as a first auth factor, then activate the
    # passkey relying party.
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags=_TAGS,
        UserPoolTier="ESSENTIALS",
        Policies={
            **_LENIENT_POLICY,
            "SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "WEB_AUTHN"]},
        },
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    c.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        WebAuthnConfiguration={"RelyingPartyId": _RELYING_PARTY_ID, "UserVerification": "preferred"},
    )

    client_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_AUTH",
        ],
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))

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

    auth = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]
    access_token = auth["AccessToken"]

    # Ground truth: a fresh user has zero registered passkeys.
    before = c.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    assert before == [], f"expected no webauthn credentials for a fresh user, got {before}"

    # Positive control: register one real passkey, so the delete under test has a
    # genuine target it must be able to succeed against.
    real_credential_id = _register_webauthn_credential(c, access_token)
    creds = c.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    ids = {cred["CredentialId"] for cred in creds}
    assert real_credential_id in ids, f"registered credential missing from list: {ids}"

    # The negative under test: a CredentialId never registered for this caller is
    # rejected, and the real credential is untouched by the rejected attempt.
    code, message = _error(
        lambda: c.delete_web_authn_credential(
            AccessToken=access_token, CredentialId="nonexistent-credential-id"
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "The credential does not exist", f"unexpected message {message!r}"
    creds = c.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    ids = {cred["CredentialId"] for cred in creds}
    assert real_credential_id in ids, f"real credential disappeared after a rejected bogus delete: {ids}"

    # The identical operation against the real credential succeeds, and an
    # independent read confirms it gone.
    c.delete_web_authn_credential(AccessToken=access_token, CredentialId=real_credential_id)
    creds = c.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    ids = {cred["CredentialId"] for cred in creds}
    assert real_credential_id not in ids, f"real credential still listed after delete: {ids}"

    # And the now-deleted id behaves exactly like an id that was never registered
    # at all -- the delete provably left it gone and unusable.
    code, message = _error(
        lambda: c.delete_web_authn_credential(AccessToken=access_token, CredentialId=real_credential_id)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on re-delete of the now-deleted credential, got {code}"
    )
    assert message == "The credential does not exist", f"unexpected re-delete message {message!r}"


def _register_webauthn_credential(c, access_token: str) -> str:
    options = c.start_web_authn_registration(AccessToken=access_token)["CredentialCreationOptions"]
    assert "challenge" in options and "rp" in options, f"malformed CredentialCreationOptions: {options}"
    rp_id = options["rp"]["id"]

    credential_id = os.urandom(32)
    # "none"-format attestation carries no attestation signature, so a fixed valid
    # P-256 base point is sufficient as the stand-in public key here.
    cose_key = _cbor_encode({1: 2, 3: -7, -1: 1, -2: _P256_GX, -3: _P256_GY})
    rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    flags = bytes([0x41])  # UP (0x01) | AT (0x40)
    sign_count = (0).to_bytes(4, "big")
    aaguid = b"\x00" * 16
    cred_id_len = len(credential_id).to_bytes(2, "big")
    auth_data = rp_id_hash + flags + sign_count + aaguid + cred_id_len + credential_id + cose_key
    attestation_object = _cbor_encode({"fmt": "none", "attStmt": {}, "authData": auth_data})

    client_data = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": options["challenge"],
            "origin": f"https://{rp_id}",
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode("utf-8")

    credential = {
        "id": _b64url(credential_id),
        "rawId": _b64url(credential_id),
        "type": "public-key",
        "clientExtensionResults": {},
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": _b64url(client_data),
            "attestationObject": _b64url(attestation_object),
            "transports": ["internal"],
        },
    }
    c.complete_web_authn_registration(AccessToken=access_token, Credential=credential)
    return _b64url(credential_id)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _cbor_encode(obj) -> bytes:
    """Minimal RFC 8949 CBOR encoder for the ints/bytes/str/map shapes a WebAuthn
    'none'-format attestation needs."""
    if isinstance(obj, bool):
        return b"\xf5" if obj else b"\xf4"
    if isinstance(obj, int):
        return _cbor_len(0, obj) if obj >= 0 else _cbor_len(1, -1 - obj)
    if isinstance(obj, bytes):
        return _cbor_len(2, len(obj)) + obj
    if isinstance(obj, str):
        raw = obj.encode("utf-8")
        return _cbor_len(3, len(raw)) + raw
    if isinstance(obj, dict):
        out = _cbor_len(5, len(obj))
        for k, v in obj.items():
            out += _cbor_encode(k) + _cbor_encode(v)
        return out
    raise TypeError(f"unsupported CBOR type: {type(obj)!r}")


def _cbor_len(major: int, length: int) -> bytes:
    if length < 24:
        return bytes([(major << 5) | length])
    if length < 256:
        return bytes([(major << 5) | 24, length])
    if length < 65536:
        return bytes([(major << 5) | 25]) + length.to_bytes(2, "big")
    return bytes([(major << 5) | 26]) + length.to_bytes(4, "big")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
