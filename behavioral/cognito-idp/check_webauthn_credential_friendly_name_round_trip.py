"""webauthn-credential-friendly-name-round-trip."""
from __future__ import annotations

import base64
import hashlib
import json
import secrets

from behavioral_harness import tags

CHECK = "webauthn-credential-friendly-name-round-trip"
GROUP = "representation"
SERVICES = ["cognito-idp"]

_RP_ID = "localhost"
_ORIGIN = "https://localhost"


@tags("axis:rejection", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartWebAuthnRegistration offers a challenge for the relying party; CompleteWebAuthnRegistration with
    a self-attested credential fails with InvalidParameterException "Credential data is not valid" and
    leaves none, or, if accepted, the generated FriendlyCredentialName is the same on two reads."""
    from botocore.exceptions import ClientError

    from cryptography.hazmat.primitives.asymmetric import ec

    cognito = ctx.client("cognito-idp")
    pool_id, access_token = _setup_webauthn_user(ctx, _RP_ID)

    start = cognito.start_web_authn_registration(AccessToken=access_token)
    options = start["CredentialCreationOptions"]
    # Positive control: the account and credentials are healthy for the WebAuthn flow up
    # to this point -- a bad token or a misconfigured pool would fail here, not later.
    assert options.get("challenge"), f"StartWebAuthnRegistration returned no challenge: {options!r}"
    assert options.get("rp", {}).get("id") == _RP_ID, f"unexpected rp in options: {options!r}"
    assert options.get("pubKeyCredParams"), f"StartWebAuthnRegistration offered no pubKeyCredParams: {options!r}"

    credential, _cred_id_b64 = _build_registration_credential(ec, options, _RP_ID, _ORIGIN)

    try:
        cognito.complete_web_authn_registration(AccessToken=access_token, Credential=credential)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
        assert code == "InvalidParameterException", (
            f"expected the attestation-validation refusal InvalidParameterException, got {code}: {message}"
        )
        assert message == "Credential data is not valid", (
            f"expected the credential-validity refusal 'Credential data is not valid', got "
            f"InvalidParameterException with a different message: {message!r}"
        )
        remaining = cognito.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
        assert remaining == [], (
            f"CompleteWebAuthnRegistration was refused but a credential still appears in "
            f"ListWebAuthnCredentials: {remaining!r}"
        )
        return

    # AWS accepted the self-attested credential -- the withdrawal above no longer holds
    # in this account/service version. Fall back to the representation contract this
    # check exists to name: the server-generated FriendlyCredentialName round-trips
    # byte-for-byte, stably, across independent reads.
    first = cognito.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    assert len(first) == 1, f"expected exactly one registered credential, got {first!r}"
    friendly_first = first[0]["FriendlyCredentialName"]
    assert isinstance(friendly_first, str) and friendly_first != "", (
        f"FriendlyCredentialName missing or empty: {first[0]!r}"
    )

    second = cognito.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    assert len(second) == 1, f"credential count changed between reads: {second!r}"
    friendly_second = second[0]["FriendlyCredentialName"]

    assert friendly_second == friendly_first, (
        f"FriendlyCredentialName changed between independent reads: {friendly_first!r} != {friendly_second!r}"
    )


def _setup_webauthn_user(ctx, rp_id: str):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-webauthn-pool-"),
        Policies={"SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "WEB_AUTHN"]}},
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-webauthn"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-webauthn-client-"),
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_AUTH",
        ],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        WebAuthnConfiguration={"RelyingPartyId": rp_id, "UserVerification": "preferred"},
    )

    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real-Passw0rd!23"
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    auth = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = auth["AuthenticationResult"]["AccessToken"]
    return pool_id, access_token


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _cbor_len_prefix(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    if n < 256:
        return bytes([major << 5 | 24, n])
    if n < 65536:
        return bytes([major << 5 | 25]) + n.to_bytes(2, "big")
    return bytes([major << 5 | 26]) + n.to_bytes(4, "big")


def _cbor_int(n: int) -> bytes:
    if n >= 0:
        return _cbor_len_prefix(0, n)
    return _cbor_len_prefix(1, -1 - n)


def _cbor_bytes(b: bytes) -> bytes:
    return _cbor_len_prefix(2, len(b)) + b


def _cbor_text(s: str) -> bytes:
    raw = s.encode("utf-8")
    return _cbor_len_prefix(3, len(raw)) + raw


def _cbor_map(pairs) -> bytes:
    out = _cbor_len_prefix(5, len(pairs))
    for k, v in pairs:
        out += k + v
    return out


def _build_registration_credential(ec_module, options, rp_id: str, origin: str):
    """Builds a self-attested (fmt=none) WebAuthn RegistrationResponseJSON dict."""
    priv = ec_module.generate_private_key(ec_module.SECP256R1())
    numbers = priv.public_key().public_numbers()
    x = numbers.x.to_bytes(32, "big")
    y = numbers.y.to_bytes(32, "big")

    cred_id = secrets.token_bytes(32)
    rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    flags = 0x45  # bit0 UP | bit2 UV | bit6 AT
    counter = (0).to_bytes(4, "big")
    aaguid = b"\x00" * 16

    cose_key = _cbor_map(
        [
            (_cbor_int(1), _cbor_int(2)),  # kty: EC2
            (_cbor_int(3), _cbor_int(-7)),  # alg: ES256
            (_cbor_int(-1), _cbor_int(1)),  # crv: P-256
            (_cbor_int(-2), _cbor_bytes(x)),
            (_cbor_int(-3), _cbor_bytes(y)),
        ]
    )
    attested_cred_data = aaguid + len(cred_id).to_bytes(2, "big") + cred_id + cose_key
    auth_data = rp_id_hash + bytes([flags]) + counter + attested_cred_data

    attestation_object = _cbor_map(
        [
            (_cbor_text("fmt"), _cbor_text("none")),
            (_cbor_text("attStmt"), _cbor_map([])),
            (_cbor_text("authData"), _cbor_bytes(auth_data)),
        ]
    )

    client_data = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": options["challenge"],
            "origin": origin,
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode("utf-8")

    cred_id_b64 = _b64url(cred_id)
    credential = {
        "id": cred_id_b64,
        "rawId": cred_id_b64,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "clientExtensionResults": {},
        "response": {
            "clientDataJSON": _b64url(client_data),
            "attestationObject": _b64url(attestation_object),
        },
    }
    return credential, cred_id_b64


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
