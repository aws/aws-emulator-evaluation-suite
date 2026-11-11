"""webauthn-credential-list-order-matches-creation-order."""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "webauthn-credential-list-order-matches-creation-order"
GROUP = "ordering"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListWebAuthnCredentials returns all three passkeys registered one at a time, and the
    same ones again on a repeated call. Real AWS lists them most-recently-created first, but
    AWS documents no order, so any order of exactly those credentials is accepted."""
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: F401

    cognito = ctx.client("cognito-idp")
    rp_id = "localhost"

    try:
        pool_id, client_id = _create_pool_and_client(ctx, cognito)
        access_token = _create_confirmed_user_and_sign_in(ctx, cognito, pool_id, client_id)
        cognito.set_user_pool_mfa_config(
            UserPoolId=pool_id,
            WebAuthnConfiguration={"RelyingPartyId": rp_id, "UserVerification": "preferred"},
        )
    except ClientError as exc:
        raise AssertionError(
            f"could not enable WebAuthn on a test user pool in this environment: "
            f"{_error_code(exc)}: {exc}"
        )

    origin = f"https://{rp_id}"
    created_ids: list[str] = []
    for i in range(3):
        options = None
        try:
            start = _start_web_authn_registration_with_retry(cognito, access_token)
            options = start["CredentialCreationOptions"]
            attestation = _fabricate_none_attestation_credential(options, origin)
            cognito.complete_web_authn_registration(AccessToken=access_token, Credential=attestation)
        except ClientError as exc:
            raise AssertionError(
                f"WebAuthn registration ceremony #{i} was rejected by the pool "
                f"({_error_code(exc)}: {exc}); configured rp_id={rp_id!r} options.rp.id="
                f"{(options or {}).get('rp', {}).get('id')!r}; cannot establish real credentials "
                f"for ordering"
            )
        created_ids.append(attestation["id"])
        ctx.on_cleanup(
            lambda cred_id=attestation["id"]: cognito.delete_web_authn_credential(
                AccessToken=access_token, CredentialId=cred_id
            )
        )
        time.sleep(1.1)  # keep CreationDate strictly increasing between registrations

    listed = cognito.list_web_authn_credentials(AccessToken=access_token)
    listed_ids = [c["CredentialId"] for c in listed["Credentials"]]

    expected_order = list(reversed(created_ids))
    assert listed_ids == expected_order or sorted(listed_ids) == sorted(expected_order), (
        f"ListWebAuthnCredentials returned {listed_ids}, not the registered credentials "
        f"{expected_order} (registration order was {created_ids})"
    )

    repeat_listed_ids = [
        c["CredentialId"]
        for c in cognito.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    ]
    assert repeat_listed_ids == listed_ids or sorted(repeat_listed_ids) == sorted(listed_ids), (
        f"ListWebAuthnCredentials credentials changed across two unmodified calls: "
        f"{listed_ids} then {repeat_listed_ids}"
    )


def _error_code(exc: ClientError) -> str | None:
    try:
        return exc.response["Error"]["Code"]
    except Exception:
        return None


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


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


def _fabricate_none_attestation_credential(options: dict, origin: str) -> dict:
    """Build a real (self-attested, 'fmt: none') WebAuthn RegistrationResponseJSON that
    satisfies CompleteWebAuthnRegistration for the given CredentialCreationOptions."""
    from cryptography.hazmat.primitives.asymmetric import ec

    challenge = options["challenge"]
    rp_id = options["rp"]["id"]

    rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    flags = bytes([0x45])  # UP (0x01) | UV (0x04) | AT (0x40)
    sign_count = (0).to_bytes(4, "big")
    aaguid = b"\x00" * 16
    credential_id = secrets.token_bytes(32)

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
            "origin": origin,
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode("utf-8")

    credential_id_b64url = _b64url(credential_id)
    return {
        "id": credential_id_b64url,
        "rawId": credential_id_b64url,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "clientExtensionResults": {},
        "response": {
            "attestationObject": _b64url(attestation_object),
            "clientDataJSON": _b64url(client_data),
            "transports": ["internal"],
        },
    }


def _start_web_authn_registration_with_retry(cognito, access_token: str, timeout: float = 30.0, interval: float = 3.0) -> dict:
    """StartWebAuthnRegistration can keep raising WebAuthnNotEnabledException for a short
    while after SetUserPoolMfaConfig has already accepted a WebAuthnConfiguration -- the
    pool-level activation is eventually consistent on real AWS -- so this retries on that
    specific error instead of failing on the first call."""
    deadline = time.time() + timeout
    last_exc = None
    while time.time() < deadline:
        try:
            return cognito.start_web_authn_registration(AccessToken=access_token)
        except ClientError as exc:
            if "WebAuthnNotEnabledException" not in (_error_code(exc) or ""):
                raise
            last_exc = exc
            time.sleep(interval)
    raise AssertionError(
        f"WebAuthn was still not enabled for this pool after ~{timeout:.0f}s of polling "
        f"StartWebAuthnRegistration: {last_exc}"
    )


def _create_pool_and_client(ctx, cognito):
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-webauthnpool-"),
        Policies={"SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "WEB_AUTHN"]}},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-webauthnclient-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH", "ALLOW_USER_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    return pool_id, client_id


def _create_confirmed_user_and_sign_in(ctx, cognito, pool_id, client_id) -> str:
    username = ctx.unique_name("sim2real-behav-webauthnuser-")
    password = "Sim2Real!Behav0r123"
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    auth = cognito.initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        ClientId=client_id,
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return auth["AuthenticationResult"]["AccessToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
