"""complete-webauthn-registration-malformed-attestation-rejected."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "complete-webauthn-registration-malformed-attestation-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

# NIST P-256 base-point coordinates as the simulated authenticator's public key: attestation
# format "none" carries no signature, so a fixed valid curve point suffices without extra libraries.
_P256_GX = bytes.fromhex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
_P256_GY = bytes.fromhex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CompleteWebAuthnRegistration with an invalid Credential is refused with
    InvalidParameterException "Credential data is not valid" and the user keeps only the passkey
    registered by the valid call before it."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-webauthn-pool-"),
        UserPoolTier="ESSENTIALS",
        Policies={"SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "WEB_AUTHN"]}},
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-webauthn"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    domain = ctx.unique_name("sim2real-webauthn-dom-").lower().replace("_", "-")
    cognito.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    ctx.on_cleanup(lambda: cognito.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id))
    _wait_domain_exists(ctx, pool_id, domain)

    relying_party_id = f"{domain}.auth.{ctx.region}.amazoncognito.com"
    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        WebAuthnConfiguration={
            "RelyingPartyId": relying_party_id,
            "UserVerification": "preferred",
            "FactorConfiguration": "SINGLE_FACTOR",
        },
    )

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-webauthn-client-"),
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_AUTH",
        ],
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-webauthn-user-")
    password = "TestPassw0rd!23"
    cognito.admin_create_user(
        UserPoolId=pool_id, Username=username, TemporaryPassword=password, MessageAction="SUPPRESS"
    )
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    auth = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = auth["AuthenticationResult"]["AccessToken"]

    # Positive control: the pipeline really does accept a well-formed registration --
    # without this, "rejects a malformed attestation" is indistinguishable from "rejects
    # every CompleteWebAuthnRegistration call".
    options = cognito.start_web_authn_registration(AccessToken=access_token)["CredentialCreationOptions"]
    assert "challenge" in options and "rp" in options, options
    valid_credential = _build_registration_credential(options, relying_party_id)
    cognito.complete_web_authn_registration(AccessToken=access_token, Credential=valid_credential)
    after_valid = {
        c["CredentialId"] for c in cognito.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    }
    assert after_valid == {valid_credential["id"]}, after_valid

    # Break exactly one thing: a fresh challenge, then a structurally invalid Credential
    # document instead of a real attestation.
    cognito.start_web_authn_registration(AccessToken=access_token)
    code, code_msg = _error_code(
        lambda: cognito.complete_web_authn_registration(
            AccessToken=access_token, Credential={"not": "a-real-webauthn-credential"}
        )
    )
    assert code == "InvalidParameterException", code
    assert code_msg == 'Credential data is not valid', f"expected the exact {code} message, got {code_msg!r}"

    # Effect absent: the malformed attempt added no credential -- the only one on file is
    # still the one the positive control registered.
    after_malformed = {
        c["CredentialId"] for c in cognito.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    }
    assert after_malformed == {valid_credential["id"]}, after_malformed


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


def _wait_domain_exists(ctx, pool_id: str, domain: str, timeout_s: float = 60.0) -> None:
    cognito = ctx.client("cognito-idp")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = cognito.describe_user_pool_domain(Domain=domain)
            if resp.get("DomainDescription", {}).get("UserPoolId") == pool_id:
                return
        except ClientError:
            pass
        time.sleep(3.0)
    raise AssertionError(f"domain {domain} never became associated with {pool_id}")


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
    raise TypeError(f"unsupported cbor type: {type(value)!r}")


def _cbor_uint_header(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 256:
        return bytes([(major << 5) | 24, n])
    if n < 65536:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _build_registration_credential(options: dict, relying_party_id: str) -> dict:
    """Simulate a WebAuthn authenticator's registration ceremony against the
    CredentialCreationOptions returned by StartWebAuthnRegistration, producing a
    RegistrationResponseJSON-shaped Credential document for CompleteWebAuthnRegistration."""
    rp_id = options.get("rp", {}).get("id", relying_party_id)
    client_data = {
        "type": "webauthn.create",
        "challenge": options["challenge"],
        "origin": f"https://{rp_id}",
        "crossOrigin": False,
    }
    client_data_json = json.dumps(client_data, separators=(",", ":")).encode("utf-8")

    rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    flags = bytes([0x41])  # UP (bit0) + AT (bit6): user present, attested credential data
    sign_count = (0).to_bytes(4, "big")
    aaguid = b"\x00" * 16
    credential_id = os.urandom(32)
    credential_id_len = len(credential_id).to_bytes(2, "big")

    cose_key = _cbor_encode({1: 2, 3: -7, -1: 1, -2: _P256_GX, -3: _P256_GY})
    attested_credential_data = aaguid + credential_id_len + credential_id + cose_key
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
