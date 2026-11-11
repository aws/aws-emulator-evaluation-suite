"""complete-webauthn-registration-challenge-replay-rejected."""
from __future__ import annotations

import base64
import hashlib
import json
import os

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "complete-webauthn-registration-challenge-replay-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]

# Fixed, well-known NIST P-256 base-point coordinates, used as a stand-in public key for
# the simulated authenticator below. Registration under attestation format "none" carries
# no attestation signature, so a fixed valid curve point is sufficient and keeps this
# check dependency-free (no cryptography/cbor2 library required).
_P256_GX = bytes.fromhex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
_P256_GY = bytes.fromhex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Replaying the same StartWebAuthnRegistration challenge/credential in a second
    CompleteWebAuthnRegistration call is rejected instead of silently re-registering
    (or duplicating) the passkey."""
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

    username = ctx.unique_name("sim2real-webauthn-")
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

    # First completion of a fresh challenge must succeed (positive control for the setup itself).
    cidp.complete_web_authn_registration(AccessToken=access_token, Credential=credential)
    listed = cidp.list_web_authn_credentials(AccessToken=access_token)
    assert len(listed["Credentials"]) == 1, "expected exactly one registered passkey after the first completion"

    # Replaying the already-consumed challenge to register a *different* credential (a
    # distinct raw WebAuthn credential id/keypair reusing the same challenge value) must be
    # rejected -- otherwise a captured challenge could be replayed indefinitely to enroll
    # arbitrary attacker-controlled passkeys.
    replayed_challenge_credential = _build_registration_credential(options, rp_id)
    assert replayed_challenge_credential["id"] != credential["id"], "test bug: need a distinct credential id"
    code, code_msg = _error_code(
        lambda: cidp.complete_web_authn_registration(AccessToken=access_token, Credential=replayed_challenge_credential)
    )
    assert code == "WebAuthnChallengeNotFoundException", f"expected challenge-replay rejection, got {code!r}"
    assert code_msg == 'The challenge does not exist or has expired', f"expected the exact {code} message, got {code_msg!r}"

    listed_after = cidp.list_web_authn_credentials(AccessToken=access_token)
    assert len(listed_after["Credentials"]) == 1, "replay must not add or duplicate a second passkey credential"


def _create_webauthn_user_pool(ctx, cidp) -> str:
    try:
        resp = cidp.create_user_pool(
            PoolName=ctx.unique_name("sim2real-pool-"),
            UserPoolTier="ESSENTIALS",
            UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-webauthn"},
            Policies={
                "PasswordPolicy": {
                    "MinimumLength": 8,
                    "RequireUppercase": True,
                    "RequireLowercase": True,
                    "RequireNumbers": True,
                    "RequireSymbols": True,
                },
                # WebAuthn/passkey must be an allowed first-factor sign-in option at the
                # pool level -- StartWebAuthnRegistration otherwise 404s with
                # WebAuthnNotEnabledException even when WebAuthnConfiguration is set via
                # SetUserPoolMfaConfig.
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


def _error_code(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises AssertionError, so an emulator accepting what AWS refuses never reads as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
