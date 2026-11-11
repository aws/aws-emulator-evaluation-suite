"""webauthn-credential-id-round-trip."""
from __future__ import annotations

import base64
import hashlib
import json
import secrets

from behavioral_harness import tags

CHECK = "webauthn-credential-id-round-trip"
GROUP = "representation"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A 32-byte WebAuthn credential id registered with CompleteWebAuthnRegistration lists exactly once in
    ListWebAuthnCredentials and decodes to the same bytes, with no truncation or re-encoding."""
    from cryptography.hazmat.primitives.asymmetric import ec

    cognito = ctx.client("cognito-idp")
    pool_id, access_token = _setup_webauthn_user(ctx, cognito)

    start = cognito.start_web_authn_registration(AccessToken=access_token)
    options = start["CredentialCreationOptions"]

    credential, cred_id_bytes = _build_registration_credential(ec, options)

    cognito.complete_web_authn_registration(AccessToken=access_token, Credential=credential)

    creds = cognito.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    assert len(creds) == 1, f"expected exactly 1 registered credential, got {len(creds)}"

    returned_credential_id = creds[0]["CredentialId"]
    decoded = _b64_any_decode(returned_credential_id)
    assert decoded == cred_id_bytes, (
        f"CredentialId round-tripped through ListWebAuthnCredentials as {decoded!r}, "
        f"expected the original {cred_id_bytes!r}"
    )
    assert len(decoded) == len(cred_id_bytes), (
        f"decoded CredentialId length {len(decoded)} != submitted length {len(cred_id_bytes)}"
    )


def _setup_webauthn_user(ctx, cognito):
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-webauthn-pool-"),
        Policies={"SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "WEB_AUTHN"]}},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    # The passkey relying-party ID must be a domain the pool actually owns -- real
    # Cognito rejects an arbitrary RP ID like "localhost" as structurally invalid at
    # CompleteWebAuthnRegistration. Use the pool's own prefix domain.
    domain_prefix = ctx.unique_name("sim2real-webauthn-").lower().replace("_", "-").strip("-")
    cognito.create_user_pool_domain(Domain=domain_prefix, UserPoolId=pool_id)
    ctx.on_cleanup(lambda: cognito.delete_user_pool_domain(Domain=domain_prefix, UserPoolId=pool_id))
    rp_id = f"{domain_prefix}.auth.{ctx.region}.amazoncognito.com"

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-webauthn-client-"),
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_AUTH",
        ],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        WebAuthnConfiguration={"RelyingPartyId": rp_id, "UserVerification": "preferred"},
    )

    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real-Passw0rd!23"
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    auth = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = auth["AuthenticationResult"]["AccessToken"]
    return pool_id, access_token


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64_any_decode(s: str) -> bytes:
    padded = s + "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception:
        return base64.b64decode(padded)


def _cbor_len_prefix(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    if n < 256:
        return bytes([major << 5 | 24, n])
    if n < 65536:
        return bytes([major << 5 | 25]) + n.to_bytes(2, "big")
    return bytes([major << 5 | 26]) + n.to_bytes(4, "big")


def _cbor_int(n: int) -> bytes:
    if n >= 0:
        return _cbor_len_prefix(0, n)
    return _cbor_len_prefix(1, -1 - n)


def _cbor_bytes(b: bytes) -> bytes:
    return _cbor_len_prefix(2, len(b)) + b


def _cbor_text(s: str) -> bytes:
    raw = s.encode("utf-8")
    return _cbor_len_prefix(3, len(raw)) + raw


def _cbor_map(pairs) -> bytes:
    out = _cbor_len_prefix(5, len(pairs))
    for k, v in pairs:
        out += k + v
    return out


def _build_registration_credential(ec_module, options):
    """Builds a self-attested (fmt=none) WebAuthn RegistrationResponseJSON dict.

    Returns (credential_dict, raw_credential_id_bytes).
    """
    rp_id = options["rp"]["id"]
    origin = f"https://{rp_id}"
    priv = ec_module.generate_private_key(ec_module.SECP256R1())
    numbers = priv.public_key().public_numbers()
    x = numbers.x.to_bytes(32, "big")
    y = numbers.y.to_bytes(32, "big")

    cred_id = secrets.token_bytes(32)
    rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    flags = 0x45  # bit0 UP | bit2 UV | bit6 AT
    counter = (0).to_bytes(4, "big")
    aaguid = b"\x00" * 16

    cose_key = _cbor_map(
        [
            (_cbor_int(1), _cbor_int(2)),  # kty: EC2
            (_cbor_int(3), _cbor_int(-7)),  # alg: ES256
            (_cbor_int(-1), _cbor_int(1)),  # crv: P-256
            (_cbor_int(-2), _cbor_bytes(x)),
            (_cbor_int(-3), _cbor_bytes(y)),
        ]
    )
    attested_cred_data = aaguid + len(cred_id).to_bytes(2, "big") + cred_id + cose_key
    auth_data = rp_id_hash + bytes([flags]) + counter + attested_cred_data

    attestation_object = _cbor_map(
        [
            (_cbor_text("fmt"), _cbor_text("none")),
            (_cbor_text("attStmt"), _cbor_map([])),
            (_cbor_text("authData"), _cbor_bytes(auth_data)),
        ]
    )

    client_data = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": options["challenge"],
            "origin": origin,
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode("utf-8")

    cred_id_b64 = _b64url(cred_id)
    credential = {
        "id": cred_id_b64,
        "rawId": cred_id_b64,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "clientExtensionResults": {},
        "response": {
            "clientDataJSON": _b64url(client_data),
            "attestationObject": _b64url(attestation_object),
            "transports": ["internal"],
        },
    }
    return credential, cred_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
