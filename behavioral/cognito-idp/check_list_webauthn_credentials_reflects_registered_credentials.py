"""list-webauthn-credentials-reflects-registered-credentials."""
from __future__ import annotations

import base64
import hashlib
import json
import os

from behavioral_harness import tags

CHECK = "list-webauthn-credentials-reflects-registered-credentials"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]

_PASSWORD = "Str0ng!Passw0rd"
_RP_ID = "localhost"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A WebAuthn credential registered with a software authenticator appears once in
    ListWebAuthnCredentials with the relying party id it was registered for, and is gone after
    DeleteWebAuthnCredential."""
    from cryptography.hazmat.primitives.asymmetric import ec

    idp = ctx.client("cognito-idp")
    pool_id, client_id = _create_pool_and_client(ctx)

    idp.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        WebAuthnConfiguration={"RelyingPartyId": _RP_ID, "UserVerification": "preferred"},
    )

    access_token = _create_confirmed_user_and_sign_in(ctx, pool_id, client_id)

    before = idp.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    assert before == [], f"expected no credentials before registration, got {before}"

    options = idp.start_web_authn_registration(AccessToken=access_token)["CredentialCreationOptions"]
    if "publicKey" in options:
        options = options["publicKey"]

    credential, credential_id_bytes = _build_registration_credential(options, ec)
    idp.complete_web_authn_registration(AccessToken=access_token, Credential=credential)

    credential_id_b64 = _b64url_encode(credential_id_bytes)

    after_register = idp.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    matching = [c for c in after_register if c["CredentialId"] == credential_id_b64]
    assert len(matching) == 1, f"registered credential not found in {after_register}"
    assert matching[0]["RelyingPartyId"] == options["rp"]["id"], (
        f"expected RelyingPartyId {options['rp']['id']!r}, got {matching[0]['RelyingPartyId']!r}"
    )

    idp.delete_web_authn_credential(AccessToken=access_token, CredentialId=credential_id_b64)

    after_delete = idp.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    assert all(c["CredentialId"] != credential_id_b64 for c in after_delete), (
        f"deleted credential {credential_id_b64} still present in {after_delete}"
    )


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _cbor_len_header(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 256:
        return bytes([(major << 5) | 24, n])
    if n < 65536:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")


def _cbor_encode(obj) -> bytes:
    """Minimal CBOR encoder covering the dict/bytes/str/int subset needed to
    build a WebAuthn "none"-format attestationObject and COSE_Key."""
    if isinstance(obj, bool):
        return b"\xf5" if obj else b"\xf4"
    if isinstance(obj, int):
        return _cbor_len_header(0, obj) if obj >= 0 else _cbor_len_header(1, -obj - 1)
    if isinstance(obj, bytes):
        return _cbor_len_header(2, len(obj)) + obj
    if isinstance(obj, str):
        b = obj.encode("utf-8")
        return _cbor_len_header(3, len(b)) + b
    if isinstance(obj, dict):
        out = _cbor_len_header(5, len(obj))
        for k, v in obj.items():
            out += _cbor_encode(k) + _cbor_encode(v)
        return out
    raise TypeError(f"unsupported type for minimal cbor encode: {type(obj)}")


def _build_registration_credential(options: dict, ec_module) -> tuple[dict, bytes]:
    """Acts as a software FIDO2 authenticator: generates an EC P-256 keypair and
    builds a valid "none"-attestation RegistrationResponseJSON for the given
    CredentialCreationOptions, per the W3C WebAuthn attestationObject format."""
    from cryptography.hazmat.backends import default_backend

    rp_id = options["rp"]["id"]
    challenge = options["challenge"]

    private_key = ec_module.generate_private_key(ec_module.SECP256R1(), default_backend())
    public_numbers = private_key.public_key().public_numbers()
    x_bytes = public_numbers.x.to_bytes(32, "big")
    y_bytes = public_numbers.y.to_bytes(32, "big")

    credential_id = os.urandom(32)
    rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    flags = bytes([0x45])  # UP (0x01) + UV (0x04) + AT (0x40)
    sign_count = (0).to_bytes(4, "big")
    aaguid = b"\x00" * 16
    cred_id_len = len(credential_id).to_bytes(2, "big")
    cose_key = _cbor_encode({1: 2, 3: -7, -1: 1, -2: x_bytes, -3: y_bytes})
    auth_data = rp_id_hash + flags + sign_count + aaguid + cred_id_len + credential_id + cose_key

    attestation_object = _cbor_encode({"fmt": "none", "attStmt": {}, "authData": auth_data})

    origin = f"https://{rp_id}"
    client_data = json.dumps(
        {"type": "webauthn.create", "challenge": challenge, "origin": origin, "crossOrigin": False},
        separators=(",", ":"),
    ).encode("utf-8")

    credential = {
        "id": _b64url_encode(credential_id),
        "rawId": _b64url_encode(credential_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": _b64url_encode(client_data),
            "attestationObject": _b64url_encode(attestation_object),
            "transports": ["internal"],
        },
        "clientExtensionResults": {},
        "authenticatorAttachment": "platform",
    }
    return credential, credential_id


def _create_pool_and_client(ctx) -> tuple[str, str]:
    idp = ctx.client("cognito-idp")
    # WebAuthn/passkeys are only enabled for a pool whose SignInPolicy explicitly
    # lists WEB_AUTHN as an allowed first-auth-factor (undocumented-in-API-reference
    # prerequisite; without it StartWebAuthnRegistration raises WebAuthnNotEnabledException
    # even after SetUserPoolMfaConfig(WebAuthnConfiguration=...)).
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        Policies={"SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "WEB_AUTHN"]}},
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-pool"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_AUTH",
        ],
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    return pool_id, client_id


def _create_confirmed_user_and_sign_in(ctx, pool_id: str, client_id: str) -> str:
    idp = ctx.client("cognito-idp")
    username = ctx.unique_name("sim2real-user-")
    # With WEB_AUTHN listed as an allowed first-auth-factor, the pool requires a
    # password to be set at creation time (AdminCreateUser otherwise rejects with
    # InvalidParameterException: "User is required to have a password.").
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        TemporaryPassword=_PASSWORD,
    )
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=_PASSWORD, Permanent=True
    )
    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
    )
    return auth["AuthenticationResult"]["AccessToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
