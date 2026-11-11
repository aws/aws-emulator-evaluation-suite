"""webauthn-registration-exceeds-credential-limit-rejected."""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "webauthn-registration-exceeds-credential-limit-rejected"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With 20 passkeys registered (the documented per-user quota), a 21st registration is
    rejected with LimitExceededException and the exact message, the credential set is unchanged,
    and deleting one frees a slot for a new registration."""
    from cryptography.hazmat.primitives.asymmetric import ec

    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-webauthn-limit-pool-"),
        UserPoolTier="ESSENTIALS",
        Policies={"SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "WEB_AUTHN"]}},
        UserPoolTags={"sim2real-check": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    domain = _sanitize_domain(ctx.unique_name("sim2realwalim"))
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
        ClientName=ctx.unique_name("sim2real-webauthn-limit-client-"),
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_AUTH",
        ],
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-webauthn-limit-user-")
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

    def _register_one() -> str:
        options = idp.start_web_authn_registration(AccessToken=access_token)["CredentialCreationOptions"]
        credential = _fabricate_none_attestation_credential(ec, options, origin)
        idp.complete_web_authn_registration(AccessToken=access_token, Credential=credential)
        return credential["id"]

    registered = [_register_one() for _ in range(20)]
    listed = idp.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    assert len(listed) == 20, len(listed)

    code, message = _error(_register_one)
    assert code == "LimitExceededException", code
    expected = "The limit for registered WebAuthn credentials is: 20."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    listed_after_reject = idp.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    assert len(listed_after_reject) == 20, len(listed_after_reject)
    after_reject_ids = {c["CredentialId"] for c in listed_after_reject}
    assert after_reject_ids == set(registered), (after_reject_ids, set(registered))

    idp.delete_web_authn_credential(AccessToken=access_token, CredentialId=registered[0])
    new_id = _register_one()
    final_listed = idp.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    assert len(final_listed) == 20, len(final_listed)
    final_ids = {c["CredentialId"] for c in final_listed}
    assert new_id in final_ids, (new_id, final_ids)


def _error(fn):
    """Call fn() and return its ClientError (code, message); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
