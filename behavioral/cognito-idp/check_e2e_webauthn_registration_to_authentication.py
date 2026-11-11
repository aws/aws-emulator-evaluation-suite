"""e2e-webauthn-registration-to-authentication."""
from __future__ import annotations

import hashlib
import json
import os
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-webauthn-registration-to-authentication"
GROUP = "e2e"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A passkey registered with a P-256 "none" attestation is listed, completes a WEB_AUTHN
    sign-in challenge with a signed assertion, and is gone from the list after deletion.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-webauthn-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-webauthn"},
        DeletionProtection="INACTIVE",
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
            }
        },
        UserPoolTier="ESSENTIALS",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    domain = ctx.unique_name("sim2realwebauthn").lower().replace("_", "")
    cognito.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)

    def _cleanup_domain():
        # Bounded at 20s so the pool-delete cleanup (run after this, LIFO) still fits the
        # shared 60s cleanup budget.
        cognito.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                cognito.describe_user_pool_domain(Domain=domain)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                return
            time.sleep(3)

    ctx.on_cleanup(_cleanup_domain)
    _poll_until(
        lambda: cognito.describe_user_pool_domain(Domain=domain)["DomainDescription"],
        lambda desc: desc.get("Status") == "ACTIVE",
        timeout_s=180,
        interval_s=5,
    )

    relying_party_id = "localhost"
    origin = f"https://{relying_party_id}"
    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        WebAuthnConfiguration={"RelyingPartyId": relying_party_id, "UserVerification": "preferred"},
    )
    # WebAuthnConfiguration alone only sets the relying-party/verification settings;
    # the passkey feature itself must be turned on as an allowed first-factor sign-in
    # method, or StartWebAuthnRegistration raises WebAuthnNotEnabledException.
    cognito.update_user_pool(
        UserPoolId=pool_id,
        Policies={
            "SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "WEB_AUTHN"]},
        },
    )

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-webauthn-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=[
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_USER_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
        ],
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("s2rwebauthnuser")
    password = "Str0ngPassw0rd!"
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}],
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    login = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = login["AuthenticationResult"]["AccessToken"]

    options = cognito.start_web_authn_registration(AccessToken=access_token)[
        "CredentialCreationOptions"
    ]
    algs = {p["alg"] for p in options["pubKeyCredParams"]}
    assert -7 in algs, f"ES256 (alg -7) not offered: {algs}"
    assert options["rp"]["id"] == relying_party_id, (
        f"expected rp.id {relying_party_id!r}, got {options['rp']['id']!r}"
    )

    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    pub_x = numbers.x.to_bytes(32, "big")
    pub_y = numbers.y.to_bytes(32, "big")
    credential_id = os.urandom(32)

    auth_data = _webauthn_auth_data(relying_party_id, 0, credential_id, pub_x, pub_y)
    attestation_object = _cbor_encode({"fmt": "none", "attStmt": {}, "authData": auth_data})
    client_data_reg = json.dumps(
        {"type": "webauthn.create", "challenge": options["challenge"], "origin": origin, "crossOrigin": False}
    ).encode()

    registration_credential = {
        "id": _b64url_encode(credential_id),
        "rawId": _b64url_encode(credential_id),
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "clientExtensionResults": {},
        "response": {
            "clientDataJSON": _b64url_encode(client_data_reg),
            "attestationObject": _b64url_encode(attestation_object),
            "transports": ["internal"],
        },
    }
    cognito.complete_web_authn_registration(
        AccessToken=access_token, Credential=registration_credential
    )

    creds = cognito.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    cred_ids = {c["CredentialId"] for c in creds}
    assert _b64url_encode(credential_id) in cred_ids, (
        f"expected credential {_b64url_encode(credential_id)!r} in ListWebAuthnCredentials, got {cred_ids}"
    )

    challenge_resp = cognito.initiate_auth(
        AuthFlow="USER_AUTH",
        ClientId=client_id,
        AuthParameters={"USERNAME": username, "PREFERRED_CHALLENGE": "WEB_AUTHN"},
    )
    assert challenge_resp["ChallengeName"] == "WEB_AUTHN", (
        f"expected ChallengeName 'WEB_AUTHN', got {challenge_resp['ChallengeName']!r}"
    )
    request_options = json.loads(challenge_resp["ChallengeParameters"]["CREDENTIAL_REQUEST_OPTIONS"])
    assert request_options["rpId"] == relying_party_id, (
        f"expected challenge rpId {relying_party_id!r}, got {request_options['rpId']!r}"
    )

    assertion_auth_data = _webauthn_auth_data(relying_party_id, 1, None, None, None)
    client_data_auth = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": request_options["challenge"],
            "origin": origin,
            "crossOrigin": False,
        }
    ).encode()
    signature = private_key.sign(
        assertion_auth_data + hashlib.sha256(client_data_auth).digest(), ec.ECDSA(hashes.SHA256())
    )
    assertion_credential = {
        "id": _b64url_encode(credential_id),
        "rawId": _b64url_encode(credential_id),
        "type": "public-key",
        "clientExtensionResults": {},
        "response": {
            "clientDataJSON": _b64url_encode(client_data_auth),
            "authenticatorData": _b64url_encode(assertion_auth_data),
            "signature": _b64url_encode(signature),
        },
    }
    completed = cognito.respond_to_auth_challenge(
        ClientId=client_id,
        ChallengeName="WEB_AUTHN",
        Session=challenge_resp["Session"],
        ChallengeResponses={"USERNAME": username, "CREDENTIAL": json.dumps(assertion_credential)},
    )
    assert "AccessToken" in completed["AuthenticationResult"], (
        f"expected AccessToken after WEB_AUTHN RespondToAuthChallenge, got keys "
        f"{list(completed['AuthenticationResult'].keys())}"
    )

    cognito.delete_web_authn_credential(
        AccessToken=access_token, CredentialId=_b64url_encode(credential_id)
    )
    remaining = cognito.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    remaining_ids = {c["CredentialId"] for c in remaining}
    assert _b64url_encode(credential_id) not in remaining_ids, (
        f"expected credential {_b64url_encode(credential_id)!r} gone after delete, "
        f"still present in {remaining_ids}"
    )


def _b64url_encode(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _cbor_uint(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 256:
        return bytes([(major << 5) | 24, n])
    if n < 65536:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 2**32:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")


def _cbor_encode(obj) -> bytes:
    if isinstance(obj, bool):
        return b"\xf5" if obj else b"\xf4"
    if isinstance(obj, int):
        return _cbor_uint(0, obj) if obj >= 0 else _cbor_uint(1, -1 - obj)
    if isinstance(obj, bytes):
        return _cbor_uint(2, len(obj)) + obj
    if isinstance(obj, str):
        raw = obj.encode("utf-8")
        return _cbor_uint(3, len(raw)) + raw
    if isinstance(obj, (list, tuple)):
        out = _cbor_uint(4, len(obj))
        for item in obj:
            out += _cbor_encode(item)
        return out
    if isinstance(obj, dict):
        out = _cbor_uint(5, len(obj))
        for k, v in obj.items():
            out += _cbor_encode(k)
            out += _cbor_encode(v)
        return out
    if obj is None:
        return b"\xf6"
    raise TypeError(f"unsupported cbor type {type(obj)}")


def _webauthn_auth_data(rp_id: str, sign_count: int, cred_id, pub_x, pub_y) -> bytes:
    rp_hash = hashlib.sha256(rp_id.encode()).digest()
    if cred_id is not None:
        flags = 0x45  # UP + UV + AT
        aaguid = b"\x00" * 16
        cred_len = len(cred_id).to_bytes(2, "big")
        cose_key = _cbor_encode({1: 2, 3: -7, -1: 1, -2: pub_x, -3: pub_y})
        attested = aaguid + cred_len + cred_id + cose_key
    else:
        flags = 0x05  # UP + UV, no attested credential data in an assertion
        attested = b""
    return rp_hash + bytes([flags]) + sign_count.to_bytes(4, "big") + attested


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {value}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
