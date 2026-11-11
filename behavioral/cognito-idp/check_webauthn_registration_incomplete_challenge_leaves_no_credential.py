"""webauthn-registration-incomplete-challenge-leaves-no-credential."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time

from behavioral_harness import tags

CHECK = "webauthn-registration-incomplete-challenge-leaves-no-credential"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartWebAuthnRegistration only issues a challenge: a user who never calls
    CompleteWebAuthnRegistration has no credentials, while a twin user who completes the
    ceremony lists exactly the registered one."""
    from cryptography.hazmat.primitives.asymmetric import ec

    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-webauthn-incomplete-pool-"),
        UserPoolTier="ESSENTIALS",
        Policies={"SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "WEB_AUTHN"]}},
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-webauthn-incomplete"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    domain = _sanitize_domain(ctx.unique_name("sim2realwainc"))
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
        ClientName=ctx.unique_name("sim2real-webauthn-incomplete-client-"),
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_AUTH",
        ],
    )["UserPoolClient"]["ClientId"]

    complete_token = _create_user_and_authenticate(ctx, idp, pool_id, client_id, "complete")
    incomplete_token = _create_user_and_authenticate(ctx, idp, pool_id, client_id, "incomplete")

    # Positive control: without it, a target that never stores credentials would pass the
    # empty-list assertion below.
    options = idp.start_web_authn_registration(AccessToken=complete_token)["CredentialCreationOptions"]
    credential = _build_webauthn_credential(options, ec)
    idp.complete_web_authn_registration(AccessToken=complete_token, Credential=credential)
    completed = idp.list_web_authn_credentials(AccessToken=complete_token)["Credentials"]
    assert len(completed) == 1 and completed[0]["CredentialId"] == credential["id"], completed

    start_resp = idp.start_web_authn_registration(AccessToken=incomplete_token)
    assert "CredentialCreationOptions" in start_resp

    # Deliberately never call CompleteWebAuthnRegistration.
    credentials = idp.list_web_authn_credentials(AccessToken=incomplete_token)["Credentials"]
    assert credentials == [], credentials


def _sanitize_domain(raw: str) -> str:
    """Cognito domain prefixes must be lowercase alnum/hyphen, starting and ending alnum."""
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


def _create_user_and_authenticate(ctx, idp, pool_id: str, client_id: str, role: str) -> str:
    username = ctx.unique_name(f"sim2real-webauthn-incomplete-{role}-user-")
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
    return auth["AuthenticationResult"]["AccessToken"]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _cbor_len(major: int, length: int) -> bytes:
    if length < 24:
        return bytes([(major << 5) | length])
    if length < 256:
        return bytes([(major << 5) | 24, length])
    if length < 65536:
        return bytes([(major << 5) | 25]) + length.to_bytes(2, "big")
    return bytes([(major << 5) | 26]) + length.to_bytes(4, "big")


def _cbor_encode(obj) -> bytes:
    """Minimal RFC 8949 CBOR encoder for the shapes a "none"-attestation WebAuthn
    attestationObject and COSE key need."""
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
            out += _cbor_encode(k)
            out += _cbor_encode(v)
        return out
    raise TypeError(f"unsupported CBOR type: {type(obj)}")


def _build_webauthn_credential(options: dict, ec_module) -> dict:
    """Build a "none"-attestation registration credential for the given options: empty attStmt,
    so only well-formed authenticatorData with a real P-256 COSE public key is needed."""
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
