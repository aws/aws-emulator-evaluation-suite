"""complete-webauthn-registration-malformed-credential-rejected."""
from __future__ import annotations

import base64
import hashlib
import json
import os

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "complete-webauthn-registration-malformed-credential-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_PASSWORD = "Sim2Real!Test123"

# NIST P-256 base-point coordinates as the simulated authenticator's public key: attestation
# format "none" carries no signature, so a fixed valid curve point suffices without extra libraries.
_P256_GX = bytes.fromhex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
_P256_GY = bytes.fromhex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CompleteWebAuthnRegistration with a Credential that is not a valid attestation is refused
    with InvalidParameterException "Credential data is not valid" and registers nothing, while a
    well-formed Credential registers one passkey."""
    cognito = ctx.client("cognito-idp")
    pool_id, client_id, username = _setup_confirmed_user(ctx)
    access_token = _get_access_token(ctx, pool_id, client_id, username)

    # WebAuthn must be enabled before a Credential's shape is evaluated: WEB_AUTHN as an allowed
    # first factor, and the relying party id configured via SetUserPoolMfaConfig.
    cognito.update_user_pool(
        UserPoolId=pool_id,
        Policies={
            "PasswordPolicy": {"MinimumLength": 8},
            "SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "WEB_AUTHN"]},
        },
    )
    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        WebAuthnConfiguration={
            "FactorConfiguration": "SINGLE_FACTOR",
            "UserVerification": "preferred",
            "RelyingPartyId": "localhost",
        },
    )

    # positive control: a well-formed Credential against a fresh challenge registers a
    # real passkey, proving the pipeline accepts a *valid* submission before the malformed
    # one is shown to be rejected.
    options = cognito.start_web_authn_registration(AccessToken=access_token)["CredentialCreationOptions"]
    rp_id = options.get("rp", {}).get("id", "localhost")
    valid_credential = _build_registration_credential(options, rp_id)
    cognito.complete_web_authn_registration(AccessToken=access_token, Credential=valid_credential)
    registered = cognito.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    assert len(registered) == 1, f"expected the well-formed credential to register, got {registered}"

    # obtain a second, fresh challenge so the malformed submission is evaluated for its
    # Credential *shape* rather than being rejected earlier for having no pending challenge
    cognito.start_web_authn_registration(AccessToken=access_token)

    code, code_msg = _error_code(
        lambda: cognito.complete_web_authn_registration(
            AccessToken=access_token,
            Credential={"malformed": "not-a-real-attestation-object"},
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert code_msg == 'Credential data is not valid', f"expected the exact {code} message, got {code_msg!r}"

    # positive control: the token is otherwise still valid
    who = cognito.get_user(AccessToken=access_token)
    assert who["Username"] == username

    # effect absent: the malformed attempt registered no *additional* WebAuthn credential --
    # only the one from the positive control above is present
    creds = cognito.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    assert len(creds) == 1 and creds[0]["CredentialId"] == registered[0]["CredentialId"], (
        f"expected exactly the positive-control credential {registered}, got {creds}"
    )


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


def _setup_confirmed_user(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-pool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_AUTH",
        ],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    username = ctx.unique_name("sim2real-behav-user-")
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=_PASSWORD,
        MessageAction="SUPPRESS",
        UserAttributes=[
            {"Name": "email", "Value": f"{username}@example.com"},
            {"Name": "email_verified", "Value": "true"},
        ],
    )
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=_PASSWORD, Permanent=True)
    return pool_id, client_id, username


def _get_access_token(ctx, pool_id, client_id, username):
    cognito = ctx.client("cognito-idp")
    resp = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
    )
    return resp["AuthenticationResult"]["AccessToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
