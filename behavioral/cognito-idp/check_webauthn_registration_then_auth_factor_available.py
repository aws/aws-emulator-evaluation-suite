"""webauthn-registration-then-auth-factor-available."""
from __future__ import annotations

import base64
import hashlib
import json
import os

from behavioral_harness import tags

CHECK = "webauthn-registration-then-auth-factor-available"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After Start/CompleteWebAuthnRegistration, GetUserAuthFactors transitions
    to include WEB_AUTHN as an available authentication factor for the user."""
    from cryptography.hazmat.primitives.asymmetric import ec

    cognito = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx, cognito)
    domain_prefix, rp_id = _create_domain(ctx, cognito, pool_id)
    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        MfaConfiguration="OPTIONAL",
        SoftwareTokenMfaConfiguration={"Enabled": True},
        WebAuthnConfiguration={"RelyingPartyId": rp_id, "UserVerification": "preferred"},
    )
    client_id = _create_client(ctx, cognito, pool_id)
    username = ctx.unique_name("sim2real-behav-wan-user-")
    password = "P@ssw0rd12345!"
    _create_confirmed_user(cognito, pool_id, username, password)
    access_token = _sign_in(cognito, pool_id, client_id, username, password)

    before = cognito.get_user_auth_factors(AccessToken=access_token)
    assert "WEB_AUTHN" not in before.get("ConfiguredUserAuthFactors", []), before

    options = cognito.start_web_authn_registration(AccessToken=access_token)["CredentialCreationOptions"]
    credential = _build_webauthn_credential(options, ec)
    cognito.complete_web_authn_registration(AccessToken=access_token, Credential=credential)

    after = cognito.get_user_auth_factors(AccessToken=access_token)
    assert "WEB_AUTHN" in after.get("ConfiguredUserAuthFactors", []), after


def _create_pool(ctx, cognito) -> str:
    name = ctx.unique_name("sim2real-behav-wan-pool-")
    # WebAuthn/passkey configuration requires the Essentials (or higher) feature
    # tier, and the pool's SignInPolicy must explicitly allow WEB_AUTHN as a
    # first-factor alongside another factor before StartWebAuthnRegistration
    # will accept requests.
    pool_id = cognito.create_user_pool(
        PoolName=name,
        UserPoolTier="ESSENTIALS",
        Policies={"SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "WEB_AUTHN"]}},
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_domain(ctx, cognito, pool_id: str):
    # The passkey relying-party ID must be a domain the pool actually owns --
    # Cognito rejects credentials built against an arbitrary RP ID like
    # "localhost" as structurally invalid. Use the pool's own prefix domain.
    domain_prefix = ctx.unique_name("sim2real-cog-wan-").lower().replace("_", "-").strip("-")
    cognito.create_user_pool_domain(Domain=domain_prefix, UserPoolId=pool_id)
    ctx.on_cleanup(lambda: cognito.delete_user_pool_domain(Domain=domain_prefix, UserPoolId=pool_id))
    rp_id = f"{domain_prefix}.auth.{ctx.region}.amazoncognito.com"
    return domain_prefix, rp_id


def _create_client(ctx, cognito, pool_id: str) -> str:
    name = ctx.unique_name("sim2real-behav-wan-client-")
    resp = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=name,
        GenerateSecret=False,
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_AUTH",
        ],
    )
    return resp["UserPoolClient"]["ClientId"]


def _create_confirmed_user(cognito, pool_id: str, username: str, password: str) -> None:
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="Temp0rary!Pass",
        MessageAction="SUPPRESS",
    )
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)


def _sign_in(cognito, pool_id: str, client_id: str, username: str, password: str) -> str:
    resp = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return resp["AuthenticationResult"]["AccessToken"]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _cbor_len(major: int, length: int) -> bytes:
    if length < 24:
        return bytes([(major << 5) | length])
    if length < 256:
        return bytes([(major << 5) | 24, length])
    if length < 65536:
        return bytes([(major << 5) | 25]) + length.to_bytes(2, "big")
    if length < 2**32:
        return bytes([(major << 5) | 26]) + length.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + length.to_bytes(8, "big")


def _cbor_encode(obj) -> bytes:
    """Minimal RFC 8949 CBOR encoder covering exactly the shapes a WebAuthn
    authenticatorData / attestationObject / COSE key needs (ints, bytes,
    strings, maps) -- enough for a "none"-attestation registration."""
    if isinstance(obj, bool):
        return b"\xf5" if obj else b"\xf4"
    if isinstance(obj, int):
        return _cbor_len(0, obj) if obj >= 0 else _cbor_len(1, -1 - obj)
    if isinstance(obj, bytes):
        return _cbor_len(2, len(obj)) + obj
    if isinstance(obj, str):
        raw = obj.encode("utf-8")
        return _cbor_len(3, len(raw)) + raw
    if isinstance(obj, (list, tuple)):
        out = _cbor_len(4, len(obj))
        for item in obj:
            out += _cbor_encode(item)
        return out
    if isinstance(obj, dict):
        out = _cbor_len(5, len(obj))
        for k, v in obj.items():
            out += _cbor_encode(k)
            out += _cbor_encode(v)
        return out
    raise TypeError(f"unsupported CBOR type: {type(obj)}")


def _build_webauthn_credential(options: dict, ec_module) -> dict:
    """Act as a software passkey authenticator completing a registration
    ceremony described by the CredentialCreationOptions AWS returned. "none"
    attestation has an empty attStmt, so no signature over the attestation is
    required -- only a well-formed authenticatorData carrying a genuine P-256
    COSE public key, which Cognito's WebAuthn verifier parses."""
    rp_id = options["rp"]["id"]
    challenge = options["challenge"]
    credential_id = os.urandom(16)

    private_key = ec_module.generate_private_key(ec_module.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    x = numbers.x.to_bytes(32, "big")
    y = numbers.y.to_bytes(32, "big")
    cose_key = {1: 2, 3: -7, -1: 1, -2: x, -3: y}  # kty=EC2, alg=ES256, crv=P-256

    rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    flags = bytes([0x45])  # UP(0x01) | UV(0x04) | AT(0x40)
    sign_count = (0).to_bytes(4, "big")
    aaguid = b"\x00" * 16
    cred_id_len = len(credential_id).to_bytes(2, "big")
    auth_data = (
        rp_id_hash + flags + sign_count + aaguid + cred_id_len + credential_id + _cbor_encode(cose_key)
    )
    attestation_object = _cbor_encode({"fmt": "none", "attStmt": {}, "authData": auth_data})

    client_data_json = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": challenge,
            "origin": f"https://{rp_id}",
            "crossOrigin": False,
        }
    ).encode("utf-8")

    return {
        "id": _b64url(credential_id),
        "rawId": _b64url(credential_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": _b64url(client_data_json),
            "attestationObject": _b64url(attestation_object),
            "transports": ["internal"],
        },
        "clientExtensionResults": {},
        "authenticatorAttachment": "platform",
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

