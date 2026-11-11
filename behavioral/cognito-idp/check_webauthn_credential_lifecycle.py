"""webauthn-credential-lifecycle."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "webauthn-credential-lifecycle"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]

_PASSWORD = "S1mParity!Behave2024"
_RELYING_PARTY_ID = "localhost"
_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartWebAuthnRegistration + CompleteWebAuthnRegistration register a passkey; delete removes it."""
    from cryptography.hazmat.primitives.asymmetric import ec

    cognito = ctx.client("cognito-idp")
    pool_id, client_id = _create_pool_and_client(ctx)
    _create_domain(ctx, pool_id)
    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        WebAuthnConfiguration={"RelyingPartyId": _RELYING_PARTY_ID, "UserVerification": "preferred"},
        # WebAuthnConfiguration alone doesn't activate MFA/WebAuthn on real AWS: once
        # MfaConfiguration moves off OFF, the service also requires at least one of the SMS/Email/
        # Software-token MFA configurations to be provided, or it raises InvalidParameterException
        # ("SMS MFA, Email MFA, or Software Token MFA configurations must be provided").
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )

    # GetUserPoolMfaConfig read-back is just reflecting the config that was just written (no
    # eventual-consistency lag of its own), so this is a cheap/fast sanity check with a short
    # bound. The real lag lives in StartWebAuthnRegistration's readiness (handled below) and the
    # harness enforces an overall wall-clock budget for the whole check, so the two waits must not
    # both be sized as if they were independent multi-minute waits.
    _poll_until(
        lambda: cognito.get_user_pool_mfa_config(UserPoolId=pool_id)
        .get("WebAuthnConfiguration", {})
        .get("RelyingPartyId"),
        lambda value: value == _RELYING_PARTY_ID,
        timeout=15.0,
        interval=1.0,
    )

    username = ctx.unique_name("sim2real-behav-user-")
    _admin_create_confirmed_user(ctx, pool_id, username)
    access_token = _admin_password_auth(cognito, pool_id, client_id, username)["AccessToken"]

    options = _start_web_authn_registration_with_retry(cognito, access_token)["CredentialCreationOptions"]
    assert "challenge" in options and "rp" in options, (
        f"expected CredentialCreationOptions with 'challenge' and 'rp', got keys {sorted(options)}"
    )
    rp_id = options["rp"]["id"]

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_numbers = private_key.public_key().public_numbers()
    x_bytes = public_numbers.x.to_bytes(32, "big")
    y_bytes = public_numbers.y.to_bytes(32, "big")

    credential_id = os.urandom(32)
    cose_key = _cbor_encode({1: 2, 3: -7, -1: 1, -2: x_bytes, -3: y_bytes})
    rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    # Cognito's attestation parser rejects flag bits it does not recognize (BE/BS make it
    # reject the credential as invalid); UP | UV | AT is the set it accepts.
    flags = bytes([0x01 | 0x04 | 0x40])  # UP | UV | AT
    sign_count = struct.pack(">I", 0)
    aaguid = b"\x00" * 16
    cred_id_len = struct.pack(">H", len(credential_id))
    auth_data = rp_id_hash + flags + sign_count + aaguid + cred_id_len + credential_id + cose_key

    attestation_object = _cbor_encode({"fmt": "none", "attStmt": {}, "authData": auth_data})
    client_data = json.dumps(
        {"type": "webauthn.create", "challenge": options["challenge"], "origin": f"https://{rp_id}", "crossOrigin": False},
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

    cognito.complete_web_authn_registration(AccessToken=access_token, Credential=credential)

    registered_id = _b64url_encode(credential_id)
    creds = cognito.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    ids = {c["CredentialId"] for c in creds}
    assert registered_id in ids, f"expected {registered_id} in ListWebAuthnCredentials, got {ids}"

    cognito.delete_web_authn_credential(AccessToken=access_token, CredentialId=registered_id)

    creds_after = cognito.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    ids_after = {c["CredentialId"] for c in creds_after}
    assert registered_id not in ids_after, (
        f"expected {registered_id} absent from ListWebAuthnCredentials after delete, got {ids_after}"
    )

    # The delete already proved absence via an independent read; also prove the dead id is
    # unusable, not merely unlisted — an operation that worked earlier must now be refused.
    try:
        cognito.delete_web_authn_credential(AccessToken=access_token, CredentialId=registered_id)
        raise AssertionError(f"expected re-deleting {registered_id} to fail with ResourceNotFoundException, got success")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
        message = exc.response.get("Error", {}).get("Message")
        expected = "The credential does not exist"
        assert message == expected, f"expected message {expected!r}, got {message!r}"


# ===== helpers =====


def _create_pool_and_client(ctx):
    cognito = ctx.client("cognito-idp")
    # StartWebAuthnRegistration raises WebAuthnNotEnabledException until WEB_AUTHN is added to the
    # pool's SignInPolicy.AllowedFirstAuthFactors -- this is what actually turns passkeys on, not
    # UserPoolTier or MfaConfiguration.
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        Policies={"SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "WEB_AUTHN"]}},
        UserPoolTags=_TAGS,
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        # StartWebAuthnRegistration raises WebAuthnNotEnabledException with the message "USER_AUTH
        # flow is not enabled for the client" unless the client itself allows USER_AUTH, on top of
        # the pool-level SignInPolicy change above.
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    return pool_id, client_id


def _create_domain(ctx, pool_id: str) -> None:
    cognito = ctx.client("cognito-idp")
    domain = ctx.unique_name("sim2real-behav-wa").lower().replace("_", "-")
    cognito.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    ctx.on_cleanup(lambda: _delete_domain_and_wait(cognito, domain, pool_id))


def _delete_domain_and_wait(cognito, domain: str, pool_id: str, timeout: float = 45.0, interval: float = 2.0) -> None:
    # DeleteUserPoolDomain is asynchronous and DeleteUserPool (the next cleanup) fails while the
    # domain is still attached, so wait until DescribeUserPoolDomain no longer returns it.
    _ignore_errors(lambda: cognito.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id))
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            desc = cognito.describe_user_pool_domain(Domain=domain).get("DomainDescription") or {}
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if not desc.get("Domain"):
            return
        time.sleep(interval)
    raise RuntimeError(f"user pool domain {domain} still present {timeout:.0f}s after DeleteUserPoolDomain")


def _admin_create_confirmed_user(ctx, pool_id: str, username: str) -> None:
    cognito = ctx.client("cognito-idp")
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}, {"Name": "email_verified", "Value": "true"}],
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(
        lambda: _ignore_errors(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    )
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=_PASSWORD, Permanent=True)


def _admin_password_auth(cognito, pool_id: str, client_id: str, username: str) -> dict:
    resp = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
    )
    return resp["AuthenticationResult"]


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


def _ignore_errors(fn) -> None:
    """Run a teardown delete; a resource that is already gone is fine, anything else raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "UserNotFoundException"):
            raise


def _poll_until(probe, predicate, *, timeout: float = 15.0, interval: float = 1.0):
    deadline = time.time() + timeout
    value = probe()
    while time.time() < deadline:
        if predicate(value):
            return value
        time.sleep(interval)
        value = probe()
    raise AssertionError(f"condition not met within {timeout:.0f}s, last value: {value!r}")


def _start_web_authn_registration_with_retry(cognito, access_token: str, timeout: float = 30.0, interval: float = 5.0) -> dict:
    """WebAuthnNotEnabledException from StartWebAuthnRegistration is not activation lag: it means
    the pool's SignInPolicy.AllowedFirstAuthFactors is missing WEB_AUTHN or the client's
    ExplicitAuthFlows is missing ALLOW_USER_AUTH (see _create_pool_and_client).
    With both set at creation time this succeeds on the first attempt; the short retry here is only
    a defensive margin for ordinary eventual consistency, not a wait for a multi-minute activation
    step."""
    deadline = time.time() + timeout
    last_exc = None
    while time.time() < deadline:
        try:
            return cognito.start_web_authn_registration(AccessToken=access_token)
        except ClientError as exc:
            # Match on substring rather than strict equality: real AWS's wire error `Code` for
            # this operation has been observed to carry extra qualification (e.g. a fully
            # qualified shape id) rather than the bare exception name, so an exact `!=` comparison
            # spuriously treats the very error this retry exists to absorb as "unexpected" and
            # re-raises on the very first attempt instead of ever retrying.
            code = exc.response.get("Error", {}).get("Code", "")
            if "WebAuthnNotEnabledException" not in code:
                raise
            last_exc = exc
            time.sleep(interval)
    raise AssertionError(
        f"StartWebAuthnRegistration still raised WebAuthnNotEnabledException after ~{timeout:.0f}s "
        f"despite SignInPolicy/ExplicitAuthFlows enabling WEB_AUTHN/USER_AUTH at creation time: {last_exc}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
