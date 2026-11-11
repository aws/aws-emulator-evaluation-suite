"""deep-cognito-idp-3-enforce-user-auth-select-challenge-grows-with-passkey."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets

from cryptography.hazmat.primitives.asymmetric import ec

from behavioral_harness import tags

CHECK = "deep-cognito-idp-3-enforce-user-auth-select-challenge-grows-with-passkey"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """USER_AUTH with only USERNAME returns SELECT_CHALLENGE without WEB_AUTHN for two users; after
    user A registers a passkey, A's AvailableChallenges gains exactly WEB_AUTHN while user B's stay
    the same."""
    idp = ctx.client("cognito-idp")
    pool_id, client_id = _passkey_pool(ctx, idp, ["PASSWORD", "WEB_AUTHN"])

    password = _strong_password()
    user_a = _confirmed_user(ctx, idp, pool_id, password)
    user_b = _confirmed_user(ctx, idp, pool_id, password)

    before_a = _select(idp, client_id, user_a)
    before_b = _select(idp, client_id, user_b)
    assert "WEB_AUTHN" not in before_a and "PASSWORD" in before_a, (
        f"before registration user A's AvailableChallenges should offer PASSWORD but not WEB_AUTHN, "
        f"got {before_a!r}"
    )
    assert set(before_b) == set(before_a), (
        f"two fresh users in one pool should be offered the same challenges: A={before_a!r} B={before_b!r}"
    )

    token = idp.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": user_a, "PASSWORD": password},
    )["AuthenticationResult"]["AccessToken"]
    options = idp.start_web_authn_registration(AccessToken=token)["CredentialCreationOptions"]
    idp.complete_web_authn_registration(AccessToken=token, Credential=_build_webauthn_credential(options))
    factors = idp.get_user_auth_factors(AccessToken=token).get("ConfiguredUserAuthFactors", [])
    assert "WEB_AUTHN" in factors, f"registration should configure WEB_AUTHN for user A, got {factors!r}"

    after_a = _select(idp, client_id, user_a)
    after_b = _select(idp, client_id, user_b)
    assert set(after_a) > set(before_a), (
        f"user A's AvailableChallenges must GROW strictly after registering a passkey: "
        f"before={before_a!r} after={after_a!r}"
    )
    assert set(after_a) - set(before_a) == {"WEB_AUTHN"}, (
        f"the only new challenge should be WEB_AUTHN, got added={sorted(set(after_a) - set(before_a))!r}"
    )
    assert set(after_b) == set(before_b), (
        f"twin user B registered nothing; its AvailableChallenges must not change: "
        f"before={before_b!r} after={after_b!r}"
    )


def _strong_password() -> str:
    return "Aa1!" + secrets.token_urlsafe(18)


def _passkey_pool(ctx, idp, factors):
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-uauth-"),
        UserPoolTier="ESSENTIALS",
        Policies={"SignInPolicy": {"AllowedFirstAuthFactors": list(factors)}},
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    # The relying-party id must be a domain the pool owns, so give the pool its own prefix domain.
    domain = ctx.unique_name("sim2real-uauth-").lower().replace("_", "-").strip("-")
    idp.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    ctx.on_cleanup(lambda: idp.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id))
    idp.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        MfaConfiguration="OFF",
        WebAuthnConfiguration={
            "RelyingPartyId": f"{domain}.auth.{ctx.region}.amazoncognito.com",
            "UserVerification": "preferred",
        },
    )
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-uauth-c-"),
        ExplicitAuthFlows=["ALLOW_USER_AUTH", "ALLOW_REFRESH_TOKEN_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH"],
    )["UserPoolClient"]["ClientId"]
    return pool_id, client_id


def _confirmed_user(ctx, idp, pool_id: str, password: str) -> str:
    username = ctx.unique_name("sim2real-behav-uauth-u-")
    idp.admin_create_user(
        UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS",
        TemporaryPassword=_strong_password(),
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    return username


def _select(idp, client_id: str, username: str) -> list:
    resp = idp.initiate_auth(
        ClientId=client_id, AuthFlow="USER_AUTH", AuthParameters={"USERNAME": username},
    )
    assert resp.get("ChallengeName") == "SELECT_CHALLENGE", (
        f"USER_AUTH with only USERNAME must return SELECT_CHALLENGE, got {resp.get('ChallengeName')!r}"
    )
    challenges = resp.get("AvailableChallenges")
    assert isinstance(challenges, list) and challenges, (
        f"SELECT_CHALLENGE must carry a non-empty AvailableChallenges list, got {challenges!r}"
    )
    return challenges


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
    """Minimal RFC 8949 encoder for the shapes a "none"-attestation registration needs."""
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
            out += _cbor_encode(k) + _cbor_encode(v)
        return out
    raise TypeError(f"unsupported CBOR type: {type(obj)}")


def _build_webauthn_credential(options: dict) -> dict:
    """Act as a software passkey authenticator for the CredentialCreationOptions AWS returned."""
    rp_id = options["rp"]["id"]
    credential_id = os.urandom(16)
    numbers = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
    cose_key = {1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")}
    auth_data = (
        hashlib.sha256(rp_id.encode("utf-8")).digest()
        + bytes([0x45])  # UP | UV | AT
        + (0).to_bytes(4, "big")
        + b"\x00" * 16
        + len(credential_id).to_bytes(2, "big")
        + credential_id
        + _cbor_encode(cose_key)
    )
    attestation_object = _cbor_encode({"fmt": "none", "attStmt": {}, "authData": auth_data})
    client_data_json = json.dumps({
        "type": "webauthn.create",
        "challenge": options["challenge"],
        "origin": f"https://{rp_id}",
        "crossOrigin": False,
    }).encode("utf-8")
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
