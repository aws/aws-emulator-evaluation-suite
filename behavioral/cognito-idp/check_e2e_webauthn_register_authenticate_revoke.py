"""e2e-webauthn-register-authenticate-revoke."""
from __future__ import annotations

import base64
import hashlib
import json
import os

from behavioral_harness import tags

CHECK = "e2e-webauthn-register-authenticate-revoke"
GROUP = "e2e"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A "none"-attestation passkey registered via Start/CompleteWebAuthnRegistration is listed,
    its key completes a WEB_AUTHN challenge with an AuthenticationResult, and after
    DeleteWebAuthnCredential it no longer appears in ListWebAuthnCredentials."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-cog-webauthn-"),
        DeletionProtection="INACTIVE",
        Policies={"SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "WEB_AUTHN"]}},
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-cog-webauthn"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-cog-webauthn-client-"),
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_AUTH",
        ],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    domain_prefix = ctx.unique_name("sim2real-cog-wa-").lower().replace("_", "-").strip("-")
    cognito.create_user_pool_domain(Domain=domain_prefix, UserPoolId=pool_id)

    ctx.on_cleanup(lambda: cognito.delete_user_pool_domain(Domain=domain_prefix, UserPoolId=pool_id))
    rp_id = f"{domain_prefix}.auth.{ctx.region}.amazoncognito.com"
    origin = f"https://{rp_id}"
    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        WebAuthnConfiguration={"RelyingPartyId": rp_id, "UserVerification": "preferred"},
    )

    username = ctx.unique_name("sim2real-cog-wa-user-")
    password = "Str0ng!Passw0rd321"
    cognito.admin_create_user(
        UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS", TemporaryPassword=password
    )
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    auth = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = auth["AuthenticationResult"]["AccessToken"]

    private_key = ec.generate_private_key(ec.SECP256R1())
    credential_id = os.urandom(16)

    options = cognito.start_web_authn_registration(AccessToken=access_token)[
        "CredentialCreationOptions"
    ]
    registration_credential = _build_registration_credential(
        options, private_key, credential_id, origin
    )
    cognito.complete_web_authn_registration(AccessToken=access_token, Credential=registration_credential)

    creds_after_register = cognito.list_web_authn_credentials(AccessToken=access_token)[
        "Credentials"
    ]
    assert len(creds_after_register) == 1, (
        f"expected exactly 1 credential after registration, got {creds_after_register!r}"
    )
    registered_id = creds_after_register[0]["CredentialId"]
    assert registered_id == _b64url(credential_id), (
        f"listed credential id {registered_id!r} does not match the registered "
        f"credential id {_b64url(credential_id)!r}"
    )

    challenge_resp = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_AUTH",
        AuthParameters={"USERNAME": username, "PREFERRED_CHALLENGE": "WEB_AUTHN"},
    )
    assert challenge_resp["ChallengeName"] == "WEB_AUTHN", (
        f"expected a WEB_AUTHN challenge, got {challenge_resp.get('ChallengeName')!r}"
    )
    request_options = json.loads(challenge_resp["ChallengeParameters"]["CREDENTIAL_REQUEST_OPTIONS"])
    assert request_options["rpId"] == rp_id, (
        f"expected assertion request rpId {rp_id!r}, got {request_options['rpId']!r}"
    )

    assertion_credential = _build_assertion_credential(
        request_options, private_key, credential_id, rp_id, origin
    )
    authenticated = cognito.respond_to_auth_challenge(
        ClientId=client_id,
        ChallengeName="WEB_AUTHN",
        Session=challenge_resp["Session"],
        ChallengeResponses={"USERNAME": username, "CREDENTIAL": json.dumps(assertion_credential)},
    )
    assert "AccessToken" in authenticated["AuthenticationResult"], (
        f"WEB_AUTHN authentication did not issue an AccessToken: {authenticated!r}"
    )

    cognito.delete_web_authn_credential(AccessToken=access_token, CredentialId=registered_id)
    creds_after_delete = cognito.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    assert creds_after_delete == [], (
        f"expected no credentials after revoke, got {creds_after_delete!r}"
    )


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
    strings, lists, maps) -- enough for a "none"-attestation registration."""
    if isinstance(obj, bool):
        return b"\xf5" if obj else b"\xf4"
    if isinstance(obj, int):
        return _cbor_len(0, obj) if obj >= 0 else _cbor_len(1, -1 - obj)
    if isinstance(obj, bytes):
        return _cbor_len(2, len(obj)) + obj
    if isinstance(obj, str):
        raw = obj.encode("utf-8")
        return _cbor_len(3, len(raw)) + raw
    if isinstance(obj, list):
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
    raise TypeError(f"unsupported CBOR type {type(obj)!r}")


def _webauthn_auth_data(rp_id: str, sign_count: int, credential_id, public_numbers) -> bytes:
    rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    sign_count_bytes = sign_count.to_bytes(4, "big")
    if credential_id is not None:
        flags = bytes([0x45])  # UP(0x01) | UV(0x04) | AT(0x40) -- attested credential data present
        aaguid = b"\x00" * 16
        cred_id_len = len(credential_id).to_bytes(2, "big")
        x = public_numbers.x.to_bytes(32, "big")
        y = public_numbers.y.to_bytes(32, "big")
        cose_key = {1: 2, 3: -7, -1: 1, -2: x, -3: y}  # kty=EC2, alg=ES256, crv=P-256
        attested = aaguid + cred_id_len + credential_id + _cbor_encode(cose_key)
    else:
        flags = bytes([0x05])  # UP(0x01) | UV(0x04) -- assertion, no attested credential data
        attested = b""
    return rp_id_hash + flags + sign_count_bytes + attested


def _build_registration_credential(options: dict, private_key, credential_id: bytes, origin: str) -> dict:
    """Builds a W3C RegistrationResponseJSON for a "none"-attestation software
    passkey. "none" attestation has an empty attStmt, so no signature over the
    attestation is required -- only a well-formed authenticatorData carrying a
    genuine P-256 COSE public key, which Cognito's WebAuthn verifier parses."""
    rp_id = options["rp"]["id"]
    challenge = options["challenge"]
    public_numbers = private_key.public_key().public_numbers()

    auth_data = _webauthn_auth_data(rp_id, 0, credential_id, public_numbers)
    attestation_object = _cbor_encode({"fmt": "none", "attStmt": {}, "authData": auth_data})

    client_data = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": False,
        }
    ).encode("utf-8")

    return {
        "id": _b64url(credential_id),
        "rawId": _b64url(credential_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": _b64url(client_data),
            "attestationObject": _b64url(attestation_object),
            "transports": ["internal"],
        },
        "clientExtensionResults": {},
        "authenticatorAttachment": "platform",
    }


def _build_assertion_credential(
    request_options: dict, private_key, credential_id: bytes, rp_id: str, origin: str
) -> dict:
    """Builds a W3C AuthenticationResponseJSON: an authenticatorData with no
    attested credential data, plus an ECDSA/SHA-256 signature over
    authenticatorData || SHA-256(clientDataJSON) using the same private key that
    registered the credential -- the assertion Cognito's WEB_AUTHN challenge
    verifies against the COSE public key it stored at registration."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    auth_data = _webauthn_auth_data(rp_id, 1, None, None)
    client_data = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": request_options["challenge"],
            "origin": origin,
            "crossOrigin": False,
        }
    ).encode("utf-8")
    signature = private_key.sign(
        auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
    )

    return {
        "id": _b64url(credential_id),
        "rawId": _b64url(credential_id),
        "type": "public-key",
        "clientExtensionResults": {},
        "response": {
            "clientDataJSON": _b64url(client_data),
            "authenticatorData": _b64url(auth_data),
            "signature": _b64url(signature),
        },
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
