"""deep-cognito-idp-3-enforce-user-auth-omitted-first-factor-rejected."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets

from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.asymmetric import ec

from behavioral_harness import tags

CHECK = "deep-cognito-idp-3-enforce-user-auth-omitted-first-factor-rejected"
GROUP = "authorization"
SERVICES = ["cognito-idp"]


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A first factor omitted from AllowedFirstAuthFactors is not offered and is refused even for a
    user who holds a passkey, while the ALLOW twin pool still issues the WEB_AUTHN challenge.
    """
    idp = ctx.client("cognito-idp")
    allow_pool, allow_client = _passkey_pool(ctx, idp, ["PASSWORD", "WEB_AUTHN"])
    omit_pool, omit_client = _passkey_pool(ctx, idp, ["PASSWORD", "WEB_AUTHN"])

    password = _strong_password()
    allow_user = _confirmed_user(ctx, idp, allow_pool, password)
    omit_user = _confirmed_user(ctx, idp, omit_pool, password)
    _register_passkey(idp, allow_pool, allow_client, allow_user, password)
    omit_token = _register_passkey(idp, omit_pool, omit_client, omit_user, password)

    idp.update_user_pool(
        UserPoolId=omit_pool,
        Policies={"SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD"]}},
    )
    policy = idp.describe_user_pool(UserPoolId=omit_pool)["UserPool"]["Policies"].get("SignInPolicy", {})
    assert policy.get("AllowedFirstAuthFactors") == ["PASSWORD"], (
        f"omit pool should now allow only PASSWORD as a first factor, got {policy!r}"
    )

    allow_pref = idp.initiate_auth(
        ClientId=allow_client, AuthFlow="USER_AUTH",
        AuthParameters={"USERNAME": allow_user, "PREFERRED_CHALLENGE": "WEB_AUTHN"},
    )
    assert allow_pref.get("ChallengeName") == "WEB_AUTHN", (
        f"allow twin: PREFERRED_CHALLENGE=WEB_AUTHN should yield the WEB_AUTHN challenge, got "
        f"{allow_pref.get('ChallengeName')!r}"
    )
    assert "CREDENTIAL_REQUEST_OPTIONS" in (allow_pref.get("ChallengeParameters") or {}), (
        f"allow twin WEB_AUTHN challenge must carry CREDENTIAL_REQUEST_OPTIONS, got "
        f"{sorted((allow_pref.get('ChallengeParameters') or {}))!r}"
    )

    omit_pref = idp.initiate_auth(
        ClientId=omit_client, AuthFlow="USER_AUTH",
        AuthParameters={"USERNAME": omit_user, "PREFERRED_CHALLENGE": "WEB_AUTHN"},
    )
    assert omit_pref.get("ChallengeName") == "SELECT_CHALLENGE", (
        f"omit pool: PREFERRED_CHALLENGE for the omitted WEB_AUTHN must not be honoured; expected "
        f"SELECT_CHALLENGE, got {omit_pref.get('ChallengeName')!r}"
    )
    assert "WEB_AUTHN" not in (omit_pref.get("AvailableChallenges") or []), (
        f"omit pool must not offer WEB_AUTHN, got AvailableChallenges={omit_pref.get('AvailableChallenges')!r}"
    )

    factors = idp.get_user_auth_factors(AccessToken=omit_token).get("ConfiguredUserAuthFactors", [])
    assert "WEB_AUTHN" in factors, (
        f"the omit-pool user still holds a passkey; GetUserAuthFactors should list WEB_AUTHN, got {factors!r}"
    )

    session = _select_session(idp, omit_client, omit_user)
    code, message = _error(lambda: _answer(idp, omit_client, session, omit_user, "WEB_AUTHN"))
    assert code == "InvalidParameterException", (
        f"answering SELECT_CHALLENGE with the omitted WEB_AUTHN factor returned {code!r}, "
        f"expected InvalidParameterException"
    )
    expected_message = "The selected challenge is not available."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    session = _select_session(idp, omit_client, omit_user)
    pw_resp = _answer(idp, omit_client, session, omit_user, "PASSWORD", PASSWORD=password)
    assert "AccessToken" in (pw_resp.get("AuthenticationResult") or {}), (
        f"omit pool: the still-allowed PASSWORD factor must issue tokens, got {pw_resp!r}"
    )

    session = _select_session(idp, allow_client, allow_user)
    allow_ans = _answer(idp, allow_client, session, allow_user, "WEB_AUTHN")
    assert allow_ans.get("ChallengeName") == "WEB_AUTHN", (
        f"allow twin: answering SELECT_CHALLENGE with WEB_AUTHN must advance to the WEB_AUTHN "
        f"challenge, got {allow_ans.get('ChallengeName')!r}"
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


def _register_passkey(idp, pool_id: str, client_id: str, username: str, password: str) -> str:
    token = idp.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]["AccessToken"]
    options = idp.start_web_authn_registration(AccessToken=token)["CredentialCreationOptions"]
    idp.complete_web_authn_registration(AccessToken=token, Credential=_build_webauthn_credential(options))
    return token


def _select_session(idp, client_id: str, username: str) -> dict:
    resp = idp.initiate_auth(
        ClientId=client_id, AuthFlow="USER_AUTH", AuthParameters={"USERNAME": username},
    )
    assert resp.get("ChallengeName") == "SELECT_CHALLENGE", (
        f"USER_AUTH with only USERNAME must return SELECT_CHALLENGE, got {resp.get('ChallengeName')!r}"
    )
    return resp


def _answer(idp, client_id: str, session: dict, username: str, answer: str, **extra):
    return idp.respond_to_auth_challenge(
        ClientId=client_id,
        ChallengeName="SELECT_CHALLENGE",
        Session=session["Session"],
        ChallengeResponses={"USERNAME": username, "ANSWER": answer, **extra},
    )


class _UnexpectedSuccess(AssertionError):
    pass


def _error(fn) -> tuple[str, str]:
    try:
        resp = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise _UnexpectedSuccess(f"call expected to be refused SUCCEEDED: {resp!r}")


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
