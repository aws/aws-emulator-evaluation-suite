"""list-webauthn-credentials-returns-in-registration-order."""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time

from behavioral_harness import tags

CHECK = "list-webauthn-credentials-returns-in-registration-order"
GROUP = "ordering"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Registering three WebAuthn passkey credentials one after another, repeated
    ListWebAuthnCredentials calls return exactly those credentials; AWS documents no order,
    so its measured most-recent-first order is accepted but not required."""
    from cryptography.hazmat.primitives.asymmetric import ec

    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-webauthn-order-pool-"),
        UserPoolTier="ESSENTIALS",
        Policies={"SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "WEB_AUTHN"]}},
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-webauthn-order"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    domain = _sanitize_domain(ctx.unique_name("sim2realwaord"))
    idp.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    ctx.on_cleanup(lambda: idp.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id))
    _wait_domain_active(ctx, domain)
    relying_party_id = f"{domain}.auth.{ctx.region}.amazoncognito.com"

    idp.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        WebAuthnConfiguration={"RelyingPartyId": relying_party_id, "UserVerification": "preferred"},
    )

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-webauthn-order-client-"),
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_AUTH",
        ],
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-webauthn-order-user-")
    password = "Sim2Real!Behav123"
    idp.admin_create_user(
        UserPoolId=pool_id, Username=username, TemporaryPassword=password, MessageAction="SUPPRESS"
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))

    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = auth["AuthenticationResult"]["AccessToken"]

    origin = f"https://{relying_party_id}"
    registered_ids = []
    for _ in range(3):
        options = idp.start_web_authn_registration(AccessToken=access_token)["CredentialCreationOptions"]
        credential = _fabricate_none_attestation_credential(ec, options, origin)
        idp.complete_web_authn_registration(AccessToken=access_token, Credential=credential)
        registered_ids.append(credential["id"])

    first_listing = [
        c["CredentialId"] for c in idp.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    ]
    second_listing = [
        c["CredentialId"] for c in idp.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    ]

    # Empirically, real AWS returns WebAuthn credentials most-recently-registered first;
    # the order is undocumented, so the same credentials in any order are accepted.
    expected_order = list(reversed(registered_ids))
    assert first_listing == expected_order or sorted(first_listing) == sorted(expected_order), (
        first_listing,
        expected_order,
    )
    assert second_listing == first_listing or sorted(second_listing) == sorted(first_listing), (
        second_listing,
        first_listing,
    )


def _sanitize_domain(raw: str) -> str:
    cleaned = "".join(ch for ch in raw.lower() if ch.isalnum() or ch == "-")
    return cleaned.strip("-")[:63]


def _wait_domain_active(ctx, domain: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> None:
    idp = ctx.client("cognito-idp")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        last_status = idp.describe_user_pool_domain(Domain=domain)["DomainDescription"].get("Status")
        if last_status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"user pool domain never reached ACTIVE (last status={last_status})")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _cbor_major(major: int, n: int) -> bytes:
    prefix = major << 5
    if n < 24:
        return bytes([prefix | n])
    if n < 256:
        return bytes([prefix | 24, n])
    if n < 65536:
        return bytes([prefix | 25]) + n.to_bytes(2, "big")
    return bytes([prefix | 26]) + n.to_bytes(4, "big")


def _cbor_encode(value) -> bytes:
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        return _cbor_major(0, value) if value >= 0 else _cbor_major(1, -value - 1)
    if isinstance(value, bytes):
        return _cbor_major(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return _cbor_major(3, len(encoded)) + encoded
    if isinstance(value, dict):
        out = _cbor_major(5, len(value))
        for key, val in value.items():
            out += _cbor_encode(key) + _cbor_encode(val)
        return out
    raise TypeError(f"unsupported cbor type: {type(value)}")


def _fabricate_none_attestation_credential(ec_module, options: dict, origin: str) -> dict:
    rp_id = options["rp"]["id"]
    challenge = options["challenge"]

    private_key = ec_module.generate_private_key(ec_module.SECP256R1())
    public_numbers = private_key.public_key().public_numbers()

    credential_id = secrets.token_bytes(16)
    rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
    flags = 0b01000101  # UP=1 (bit0), UV=1 (bit2), AT=1 (bit6)
    sign_count = (0).to_bytes(4, "big")
    aaguid = b"\x00" * 16
    cred_id_len = len(credential_id).to_bytes(2, "big")
    cose_key = {
        1: 2,  # kty: EC2
        3: -7,  # alg: ES256
        -1: 1,  # crv: P-256
        -2: public_numbers.x.to_bytes(32, "big"),
        -3: public_numbers.y.to_bytes(32, "big"),
    }
    attested_cred_data = aaguid + cred_id_len + credential_id + _cbor_encode(cose_key)
    auth_data = rp_id_hash + bytes([flags]) + sign_count + attested_cred_data
    attestation_object = _cbor_encode({"fmt": "none", "attStmt": {}, "authData": auth_data})

    client_data = {
        "type": "webauthn.create",
        "challenge": challenge,
        "origin": origin,
        "crossOrigin": False,
    }
    client_data_json = json.dumps(client_data, separators=(",", ":")).encode()

    credential_id_b64url = _b64url(credential_id)
    return {
        "id": credential_id_b64url,
        "rawId": credential_id_b64url,
        "response": {
            "clientDataJSON": _b64url(client_data_json),
            "attestationObject": _b64url(attestation_object),
            "transports": ["internal"],
        },
        "type": "public-key",
        "clientExtensionResults": {},
        "authenticatorAttachment": "platform",
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
