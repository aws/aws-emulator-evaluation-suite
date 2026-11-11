"""delete-webauthn-credential-wrong-owner-rejected."""
from __future__ import annotations

import base64
import hashlib
import json
import os

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-webauthn-credential-wrong-owner-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]

# NIST P-256 base-point coordinates as the simulated authenticator's public key: attestation
# format "none" carries no signature, so a fixed valid curve point suffices without extra libraries.
_P256_GX = bytes.fromhex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
_P256_GY = bytes.fromhex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteWebAuthnCredential with another user's CredentialId answers ResourceNotFoundException
    "The credential does not exist" and leaves both users' passkeys and tokens intact, and the
    caller can still delete its own passkey."""
    cidp = ctx.client("cognito-idp")
    pool_id = _create_webauthn_user_pool(ctx, cidp)
    client_id = _create_client(ctx, cidp, pool_id)
    rp_id = "example.com"
    try:
        cidp.set_user_pool_mfa_config(
            UserPoolId=pool_id,
            WebAuthnConfiguration={"RelyingPartyId": rp_id, "UserVerification": "preferred"},
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "FeatureUnavailableInTierException":
            raise AssertionError(
                f"WebAuthn configuration not available in this account/region's tier: {exc.response['Error']['Code']}"
            ) from exc
        raise

    owner_username, owner_access_token, owner_credential_id = _register_user_with_credential(
        ctx, cidp, pool_id, client_id, rp_id, "owner"
    )
    _other_username, other_access_token, other_credential_id = _register_user_with_credential(
        ctx, cidp, pool_id, client_id, rp_id, "other"
    )

    # Break exactly one thing: a real, registered CredentialId that belongs to a *different*
    # user in the same pool -- not merely an ID nobody ever registered, which would also pass
    # against a target that enforces existence but not per-owner scope.
    code, message = _error(
        lambda: cidp.delete_web_authn_credential(AccessToken=owner_access_token, CredentialId=other_credential_id)
    )
    assert code == "ResourceNotFoundException", f"expected another user's CredentialId to be rejected, got {code!r}"
    assert message == "The credential does not exist", f"unexpected message {message!r}"

    # Effect absent: the other user's real credential is untouched.
    other_after = cidp.list_web_authn_credentials(AccessToken=other_access_token)
    assert len(other_after["Credentials"]) == 1
    assert other_after["Credentials"][0]["CredentialId"] == other_credential_id

    # Effect absent: the caller's own credential is untouched.
    owner_mid = cidp.list_web_authn_credentials(AccessToken=owner_access_token)
    assert len(owner_mid["Credentials"]) == 1
    assert owner_mid["Credentials"][0]["CredentialId"] == owner_credential_id

    # Positive control: the rejected call did not revoke the still-valid access token.
    user_resp = cidp.get_user(AccessToken=owner_access_token)
    assert user_resp["Username"] == owner_username

    # Positive control: a legitimate delete of the caller's own credential succeeds, and the
    # access token used to make that call remains valid afterward too.
    cidp.delete_web_authn_credential(AccessToken=owner_access_token, CredentialId=owner_credential_id)
    after = cidp.list_web_authn_credentials(AccessToken=owner_access_token)
    assert after["Credentials"] == []
    assert cidp.get_user(AccessToken=owner_access_token)["Username"] == owner_username


def _create_webauthn_user_pool(ctx, cidp) -> str:
    try:
        resp = cidp.create_user_pool(
            PoolName=ctx.unique_name("sim2real-pool-"),
            UserPoolTier="ESSENTIALS",
            Policies={
                "PasswordPolicy": {
                    "MinimumLength": 8,
                    "RequireUppercase": True,
                    "RequireLowercase": True,
                    "RequireNumbers": True,
                    "RequireSymbols": True,
                },
                # WEB_AUTHN must be an allowed first factor; otherwise StartWebAuthnRegistration
                # answers WebAuthnNotEnabledException even with WebAuthnConfiguration set.
                "SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "WEB_AUTHN"]},
            },
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("FeatureUnavailableInTierException", "TierChangeNotAllowedException"):
            raise AssertionError(
                "UserPoolTier=ESSENTIALS (required for passkey/WebAuthn support) is not"
                f" available in this account/region: {exc.response['Error']['Code']}"
            ) from exc
        raise
    pool_id = resp["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cidp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_client(ctx, cidp, pool_id: str) -> str:
    resp = cidp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_AUTH",
        ],
        GenerateSecret=False,
    )
    return resp["UserPoolClient"]["ClientId"]


def _register_user_with_credential(ctx, cidp, pool_id: str, client_id: str, rp_id: str, label: str):
    username = ctx.unique_name(f"sim2real-webauthn{label}-")
    password = "Sim2Real-Passw0rd!23"
    cidp.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS", TemporaryPassword=password)
    cidp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    auth = cidp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = auth["AuthenticationResult"]["AccessToken"]

    options = cidp.start_web_authn_registration(AccessToken=access_token)["CredentialCreationOptions"]
    credential = _build_registration_credential(options, rp_id)
    cidp.complete_web_authn_registration(AccessToken=access_token, Credential=credential)

    listed = cidp.list_web_authn_credentials(AccessToken=access_token)
    assert len(listed["Credentials"]) == 1, f"expected exactly one credential for {label}, got {listed['Credentials']!r}"
    credential_id = listed["Credentials"][0]["CredentialId"]
    return username, access_token, credential_id


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses cannot pass as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


def _cbor_encode(value):
    """Minimal CBOR encoder covering the types needed for a WebAuthn "none"-format
    attestation object: unsigned/negative ints, byte strings, text strings, maps."""
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        major = 0 if value >= 0 else 1
        n = value if value >= 0 else (-1 - value)
        return _cbor_uint_header(major, n)
    if isinstance(value, bytes):
        return _cbor_uint_header(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _cbor_uint_header(3, len(raw)) + raw
    if isinstance(value, dict):
        out = _cbor_uint_header(5, len(value))
        for k, v in value.items():
            out += _cbor_encode(k) + _cbor_encode(v)
        return out
    if isinstance(value, (list, tuple)):
        out = _cbor_uint_header(4, len(value))
        for item in value:
            out += _cbor_encode(item)
        return out
    raise TypeError(f"unsupported cbor type: {type(value)!r}")


def _cbor_uint_header(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 256:
        return bytes([(major << 5) | 24, n])
    if n < 65536:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 2**32:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _build_registration_credential(options: dict, relying_party_id: str) -> dict:
    """Simulate a WebAuthn authenticator's registration ceremony against the
    CredentialCreationOptions returned by StartWebAuthnRegistration, producing a
    RegistrationResponseJSON-shaped Credential document for CompleteWebAuthnRegistration."""
    rp_id = options.get("rp", {}).get("id", relying_party_id)
    challenge_b64url = options["challenge"]
    origin = f"https://{rp_id}"

    client_data = {
        "type": "webauthn.create",
        "challenge": challenge_b64url,
        "origin": origin,
        "crossOrigin": False,
    }
    client_data_json = json.dumps(client_data, separators=(",", ":")).encode("utf-8")

    rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    flags = bytes([0x41])  # UP (bit0) + AT (bit6): user present, attested credential data
    sign_count = (0).to_bytes(4, "big")
    aaguid = b"\x00" * 16
    credential_id = os.urandom(32)
    credential_id_len = len(credential_id).to_bytes(2, "big")

    cose_key = {1: 2, 3: -7, -1: 1, -2: _P256_GX, -3: _P256_GY}
    cose_key_bytes = _cbor_encode(cose_key)

    attested_credential_data = aaguid + credential_id_len + credential_id + cose_key_bytes
    auth_data = rp_id_hash + flags + sign_count + attested_credential_data

    attestation_object = _cbor_encode({"fmt": "none", "attStmt": {}, "authData": auth_data})

    return {
        "id": _b64url(credential_id),
        "rawId": _b64url(credential_id),
        "type": "public-key",
        "clientExtensionResults": {},
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": _b64url(client_data_json),
            "attestationObject": _b64url(attestation_object),
            "transports": ["internal"],
        },
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
