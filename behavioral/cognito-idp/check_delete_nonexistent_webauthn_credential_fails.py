"""delete-nonexistent-webauthn-credential-fails."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-nonexistent-webauthn-credential-fails"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]

_PASSWORD = "S1mParity!Behave2024"
_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteWebAuthnCredential for a never-registered credential id answers
    ResourceNotFoundException "The credential does not exist" and leaves the user's passkey, while
    deleting the registered passkey removes it and a repeat delete answers the same error."""
    idp = ctx.client("cognito-idp")
    pool_id, client_id = _create_pool_and_client(ctx)
    rp_id = _create_domain(ctx, pool_id)
    idp.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        WebAuthnConfiguration={"RelyingPartyId": rp_id, "UserVerification": "preferred"},
        # WebAuthnConfiguration alone doesn't activate MFA/WebAuthn on real AWS: once
        # MfaConfiguration moves off OFF, the service also requires at least one of the SMS/Email/
        # Software-token MFA configurations to be provided, or it raises InvalidParameterException.
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )
    _poll_until(
        lambda: idp.get_user_pool_mfa_config(UserPoolId=pool_id)
        .get("WebAuthnConfiguration", {})
        .get("RelyingPartyId")
        == rp_id,
        timeout=15.0,
        interval=1.0,
    )

    username = ctx.unique_name("sim2real-behav-user-")
    _admin_create_confirmed_user(ctx, pool_id, username)
    access_token = _admin_password_auth(idp, pool_id, client_id, username)["AccessToken"]

    # Ground truth: the caller has zero registered passkeys before we register one.
    creds = idp.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    assert creds == [], f"expected no webauthn credentials for a fresh user, got {creds}"

    # Positive control: register one real passkey, so the delete under test has a
    # genuine target it must be able to succeed against.
    real_credential_id = _register_webauthn_credential(idp, access_token)
    creds = idp.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    ids = {c["CredentialId"] for c in creds}
    assert real_credential_id in ids, f"registered credential missing from list: {ids}"

    # The negative under test: a credential id never registered to this caller is
    # rejected, and the real credential is untouched by the rejected attempt.
    bogus_credential_id = "sim2real-behav-never-registered-credential-id"
    code, message = _error(
        lambda: idp.delete_web_authn_credential(AccessToken=access_token, CredentialId=bogus_credential_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "The credential does not exist", message
    creds = idp.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    ids = {c["CredentialId"] for c in creds}
    assert real_credential_id in ids, f"real credential disappeared after a rejected bogus delete: {ids}"

    # The identical call against the real id succeeds, and an independent read confirms it gone.
    idp.delete_web_authn_credential(AccessToken=access_token, CredentialId=real_credential_id)
    creds = idp.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    ids = {c["CredentialId"] for c in creds}
    assert real_credential_id not in ids, f"real credential still listed after delete: {ids}"

    # And the now-deleted id behaves exactly like the id that was never registered at all.
    code, message = _error(
        lambda: idp.delete_web_authn_credential(AccessToken=access_token, CredentialId=real_credential_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException on re-delete, got {code}"
    assert message == "The credential does not exist", message


def _create_pool_and_client(ctx):
    idp = ctx.client("cognito-idp")
    # StartWebAuthnRegistration raises WebAuthnNotEnabledException until WEB_AUTHN is one of the
    # pool's SignInPolicy.AllowedFirstAuthFactors and the client allows ALLOW_USER_AUTH.
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        Policies={"SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "WEB_AUTHN"]}},
        UserPoolTags=_TAGS,
        UserPoolTier="PLUS",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    return pool_id, client_id


def _create_domain(ctx, pool_id: str) -> str:
    """Create the pool's prefix domain and return it as the passkey relying-party id.

    Cognito accepts a registration only for a relying party the pool serves (its own domain),
    and the attestation's rpIdHash and clientDataJSON origin are built from that id."""
    idp = ctx.client("cognito-idp")
    domain = ctx.unique_name("sim2real-behav-wa").lower().replace("_", "-")
    idp.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    ctx.on_cleanup(
        lambda: _unless_gone(lambda: idp.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id))
    )
    return f"{domain}.auth.{ctx.region}.amazoncognito.com"


def _admin_create_confirmed_user(ctx, pool_id: str, username: str) -> None:
    idp = ctx.client("cognito-idp")
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[
            {"Name": "email", "Value": f"{username}@example.com"},
            {"Name": "email_verified", "Value": "true"},
        ],
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(
        lambda: _unless_gone(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=_PASSWORD, Permanent=True)


def _admin_password_auth(idp, pool_id: str, client_id: str, username: str) -> dict:
    resp = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
    )
    return resp["AuthenticationResult"]


def _register_webauthn_credential(idp, access_token: str) -> str:
    from cryptography.hazmat.primitives.asymmetric import ec

    options = _start_web_authn_registration_with_retry(idp, access_token)["CredentialCreationOptions"]
    assert "challenge" in options and "rp" in options, f"malformed CredentialCreationOptions: {options}"
    rp_id = options["rp"]["id"]

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_numbers = private_key.public_key().public_numbers()
    x_bytes = public_numbers.x.to_bytes(32, "big")
    y_bytes = public_numbers.y.to_bytes(32, "big")

    credential_id = os.urandom(32)
    cose_key = _cbor_encode({1: 2, 3: -7, -1: 1, -2: x_bytes, -3: y_bytes})
    rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    flags = bytes([0x01 | 0x04 | 0x40])  # UP | UV | AT
    sign_count = struct.pack(">I", 0)
    aaguid = b"\x00" * 16
    cred_id_len = struct.pack(">H", len(credential_id))
    auth_data = rp_id_hash + flags + sign_count + aaguid + cred_id_len + credential_id + cose_key

    attestation_object = _cbor_encode({"fmt": "none", "attStmt": {}, "authData": auth_data})
    client_data = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": options["challenge"],
            "origin": f"https://{rp_id}",
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode("utf-8")

    credential = {
        "id": _b64url_encode(credential_id),
        "rawId": _b64url_encode(credential_id),
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": _b64url_encode(client_data),
            "attestationObject": _b64url_encode(attestation_object),
            "transports": ["internal"],
        },
        "clientExtensionResults": {},
    }

    idp.complete_web_authn_registration(AccessToken=access_token, Credential=credential)
    return _b64url_encode(credential_id)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _cbor_encode(obj) -> bytes:
    """Minimal canonical-ish CBOR encoder for the small set of types WebAuthn needs."""
    if isinstance(obj, bool):
        return b"\xf5" if obj else b"\xf4"
    if isinstance(obj, int):
        if obj >= 0:
            return _cbor_uint(0, obj)
        return _cbor_uint(1, -1 - obj)
    if isinstance(obj, bytes):
        return _cbor_uint(2, len(obj)) + obj
    if isinstance(obj, str):
        encoded = obj.encode("utf-8")
        return _cbor_uint(3, len(encoded)) + encoded
    if isinstance(obj, dict):
        out = _cbor_uint(5, len(obj))
        for key, value in obj.items():
            out += _cbor_encode(key)
            out += _cbor_encode(value)
        return out
    raise TypeError(f"unsupported CBOR type: {type(obj)!r}")


def _cbor_uint(major: int, value: int) -> bytes:
    head = major << 5
    if value < 24:
        return bytes([head | value])
    if value < 256:
        return bytes([head | 24, value])
    if value < 65536:
        return bytes([head | 25]) + struct.pack(">H", value)
    return bytes([head | 26]) + struct.pack(">I", value)


def _unless_gone(fn) -> None:
    """Run a teardown delete; only "it is already gone" is not a failure."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "UserNotFoundException"):
            raise


def _poll_until(predicate, timeout: float = 15.0, interval: float = 1.0) -> bool:
    deadline = time.time() + timeout
    result = False
    while time.time() < deadline:
        result = predicate()
        if result:
            return True
        time.sleep(interval)
    return result


def _start_web_authn_registration_with_retry(
    idp, access_token: str, timeout: float = 270.0, interval: float = 5.0
) -> dict:
    """StartWebAuthnRegistration can raise WebAuthnNotEnabledException for minutes after the
    pool reports WebAuthn active (activation on a new pool is eventually consistent), so retry
    on that error until the deadline."""
    deadline = time.time() + timeout
    last_exc = None
    while time.time() < deadline:
        try:
            return idp.start_web_authn_registration(AccessToken=access_token)
        except ClientError as exc:
            # Substring match: the error Code for this operation can carry a qualified shape id
            # rather than the bare exception name.
            code = exc.response.get("Error", {}).get("Code", "")
            if "WebAuthnNotEnabledException" not in code:
                raise
            last_exc = exc
            time.sleep(interval)
    raise AssertionError(
        "WebAuthn was still not enabled for this freshly created Plus-tier pool after "
        f"~{timeout:.0f}s of polling StartWebAuthnRegistration — real-AWS activation lag for a "
        f"brand new pool exceeded the check's available budget: {last_exc}"
    )


def _error(fn) -> Any:
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call to fail, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
