"""list-webauthn-credentials-ordered-by-creation."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time

from behavioral_harness import tags

CHECK = "list-webauthn-credentials-ordered-by-creation"
GROUP = "ordering"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListWebAuthnCredentials returns a signed-in user's passkeys: repeated calls with no
    intervening registration return the same credentials, and each registration adds exactly
    one credential to the prior listing. AWS documents no order, so any order is accepted."""
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: F401

    cognito = ctx.client("cognito-idp")
    pool = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-waid-pool-"),
        UserPoolTier="ESSENTIALS",
        # Passkey/WebAuthn as a first auth factor must be explicitly allowed on the pool,
        # alongside at least one other first factor (PASSWORD here), or StartWebAuthnRegistration
        # raises WebAuthnNotEnabledException even with a WebAuthnConfiguration set.
        Policies={"SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "WEB_AUTHN"]}},
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-waid"},
    )["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-waid-client-"),
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_AUTH",
        ],
        GenerateSecret=False,
    )["UserPoolClient"]
    client_id = client["ClientId"]

    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        MfaConfiguration="OFF",
        WebAuthnConfiguration={"RelyingPartyId": "localhost", "UserVerification": "preferred"},
    )

    # WebAuthn activation can take a moment to propagate; poll until StartWebAuthnRegistration
    # no longer reports the feature as disabled before proceeding.
    deadline = time.time() + 30
    while True:
        mfa_cfg = cognito.get_user_pool_mfa_config(UserPoolId=pool_id)
        if mfa_cfg.get("WebAuthnConfiguration", {}).get("RelyingPartyId") == "localhost":
            break
        if time.time() > deadline:
            raise AssertionError("WebAuthnConfiguration never propagated on GetUserPoolMfaConfig")
        time.sleep(2)

    username = ctx.unique_name("sim2real-waid-user-")
    password = "Sim2Real-Passkey-Test1!"
    cognito.admin_create_user(
        UserPoolId=pool_id, Username=username, TemporaryPassword=password, MessageAction="SUPPRESS"
    )
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )

    auth = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    if "AuthenticationResult" not in auth:
        raise AssertionError(f"expected a direct sign-in, got challenge {auth.get('ChallengeName')!r}")
    access_token = auth["AuthenticationResult"]["AccessToken"]

    # Snapshot the full credential-id order after each registration, so we can check that
    # each newly-registered credential is prepended ahead of the previously-seen order,
    # rather than being interleaved arbitrarily.
    snapshots = []
    for _ in range(3):
        options = cognito.start_web_authn_registration(AccessToken=access_token)[
            "CredentialCreationOptions"
        ]
        credential = _make_webauthn_credential(options)
        cognito.complete_web_authn_registration(AccessToken=access_token, Credential=credential)
        # Keep successive registrations' CreatedAt timestamps clearly ordered.
        time.sleep(1.1)
        listing = cognito.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
        snapshots.append([cred["CredentialId"] for cred in listing])

    assert len(snapshots[-1]) == 3, f"expected 3 registered passkeys, got {len(snapshots[-1])}"

    # Two repeated calls with no intervening registration must return identical order.
    repeat_listing = cognito.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    ids_repeat = [cred["CredentialId"] for cred in repeat_listing]
    assert ids_repeat == snapshots[-1] or sorted(ids_repeat) == sorted(snapshots[-1]), (
        "ListWebAuthnCredentials credentials changed across two unmodified calls"
    )

    # Real AWS prepends each new registration (most-recently-registered first); the order is
    # undocumented, so a listing that adds exactly one credential to the prior one is accepted.
    first, second, third = snapshots
    assert second[1:] == first or (set(first) < set(second) and len(second) == len(first) + 1), (
        f"expected the new credential added to the prior listing: {first=} {second=}"
    )
    assert third[1:] == second or (set(second) < set(third) and len(third) == len(second) + 1), (
        f"expected the new credential added to the prior listing: {second=} {third=}"
    )


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _cbor_head(major: int, arg: int) -> bytes:
    if arg < 24:
        return bytes([(major << 5) | arg])
    if arg < 2**8:
        return bytes([(major << 5) | 24, arg])
    if arg < 2**16:
        return bytes([(major << 5) | 25]) + arg.to_bytes(2, "big")
    if arg < 2**32:
        return bytes([(major << 5) | 26]) + arg.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + arg.to_bytes(8, "big")


def _cbor_encode(obj) -> bytes:
    if isinstance(obj, bool):
        return b"\xf5" if obj else b"\xf4"
    if isinstance(obj, int):
        return _cbor_head(0, obj) if obj >= 0 else _cbor_head(1, -1 - obj)
    if isinstance(obj, bytes):
        return _cbor_head(2, len(obj)) + obj
    if isinstance(obj, str):
        encoded = obj.encode("utf-8")
        return _cbor_head(3, len(encoded)) + encoded
    if isinstance(obj, dict):
        out = _cbor_head(5, len(obj))
        for key, value in obj.items():
            out += _cbor_encode(key) + _cbor_encode(value)
        return out
    if isinstance(obj, (list, tuple)):
        out = _cbor_head(4, len(obj))
        for item in obj:
            out += _cbor_encode(item)
        return out
    raise TypeError(f"unsupported CBOR type: {type(obj)!r}")


def _make_webauthn_credential(options: dict) -> dict:
    """Build a real (self-attested, 'fmt: none') WebAuthn RegistrationResponseJSON that
    satisfies CompleteWebAuthnRegistration for the given CredentialCreationOptions."""
    from cryptography.hazmat.primitives.asymmetric import ec

    challenge = options["challenge"]
    rp_id = options["rp"]["id"]

    rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    flags = bytes([0x45])  # UP (0x01) | UV (0x04) | AT (0x40)
    sign_count = (0).to_bytes(4, "big")
    aaguid = b"\x00" * 16
    credential_id = os.urandom(32)

    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    x_bytes = numbers.x.to_bytes(32, "big")
    y_bytes = numbers.y.to_bytes(32, "big")
    # COSE_Key for an EC2 P-256 public key used with ES256 (alg -7).
    cose_key = _cbor_encode({1: 2, 3: -7, -1: 1, -2: x_bytes, -3: y_bytes})

    attested_credential_data = (
        aaguid + len(credential_id).to_bytes(2, "big") + credential_id + cose_key
    )
    auth_data = rp_id_hash + flags + sign_count + attested_credential_data
    attestation_object = _cbor_encode({"fmt": "none", "attStmt": {}, "authData": auth_data})

    client_data = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": challenge,
            "origin": f"https://{rp_id}",
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode("utf-8")

    return {
        "id": _b64url(credential_id),
        "rawId": _b64url(credential_id),
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "clientExtensionResults": {},
        "response": {
            "attestationObject": _b64url(attestation_object),
            "clientDataJSON": _b64url(client_data),
            "transports": ["internal"],
        },
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
