"""forged-access-tokens-are-refused-and-verifiably-unsigned."""
from __future__ import annotations

import base64
import hashlib
import json
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "forged-access-tokens-are-refused-and-verifiably-unsigned"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]

PASSWORD = "Sup3r-Secret-Passw0rd!"
FLOWS = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_CONTROL_VALUE = "sim2real-control-value"
_FORGED_VALUE = "sim2real-value-that-must-never-land"


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Three forgeries of a genuine access token (alg:none, a rewritten payload claiming an unjoined
    group, a one-byte signature flip) are each refused by GetUser and UpdateUserAttributes, fail
    verification against the pool's JWKS, and leave the profile as the genuine token wrote it."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags=dict(_POOL_TAGS),
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _p=pool_id: c.delete_user_pool(UserPoolId=_p))
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=list(FLOWS), GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(
        lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True
    )
    # A real group the user is deliberately NOT a member of, so the injected claim names
    # something that exists in the pool and still must not authorize anything.
    group_name = ctx.unique_name("sim2real-behav-cip-privileged-")
    c.create_group(UserPoolId=pool_id, GroupName=group_name)
    ctx.on_cleanup(
        lambda _p=pool_id, _g=group_name: c.delete_group(UserPoolId=_p, GroupName=_g)
    )

    genuine = c.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]["AccessToken"]
    header_b64, payload_b64, signature_b64 = genuine.split(".")
    assert signature_b64, f"the genuine token carries no signature segment: {genuine[:32]!r}..."

    # --- positive control: the genuine token reads and writes the profile ---
    me = c.get_user(AccessToken=genuine)
    assert me["Username"] == username, (
        f"the genuine access token must identify {username} at GetUser, got "
        f"{me.get('Username')!r}"
    )
    c.update_user_attributes(
        AccessToken=genuine, UserAttributes=[{"Name": "given_name", "Value": _CONTROL_VALUE}],
    )
    control_landed = _attribute(c, pool_id, username, "given_name")
    assert control_landed == _CONTROL_VALUE, (
        f"the control write did not land: expected given_name={_CONTROL_VALUE!r}, AdminGetUser "
        f"reports {control_landed!r}"
    )

    # --- the genuine signature verifies against the published JWK, so the forgeries below are
    # being compared against a key this check has actually validated.
    header = json.loads(_b64url_decode(header_b64))
    jwk = _jwk_for_kid(c, pool_id, header.get("kid"))
    assert _verify_rs256(f"{header_b64}.{payload_b64}".encode(),
                         _b64url_decode(signature_b64), jwk), (
        "the genuine access token's RS256 signature must verify against the pool's published "
        "JWK before this check can claim the forged variants do not"
    )

    escalated = json.loads(_b64url_decode(payload_b64))
    escalated["cognito:groups"] = [group_name]
    forgeries = {
        "alg:none with the signature stripped": ".".join((
            _b64url_encode(json.dumps({**header, "alg": "none"}).encode()), payload_b64, "",
        )),
        "a cognito:groups claim injected under the original signature": ".".join((
            header_b64, _b64url_encode(json.dumps(escalated).encode()), signature_b64,
        )),
        "one flipped signature byte": ".".join((
            header_b64, payload_b64, _flip_one_byte(signature_b64),
        )),
    }

    # alg:none fails the token parse; the two RS256 forgeries fail signature verification.
    refusal_messages = {
        "alg:none with the signature stripped": "Invalid Access Token",
        "a cognito:groups claim injected under the original signature": (
            "Could not verify signature for Access Token"
        ),
        "one flipped signature byte": "Could not verify signature for Access Token",
    }

    for label, forged in forgeries.items():
        refusal_message = refusal_messages[label]
        f_header_b64, f_payload_b64, f_signature_b64 = forged.split(".")
        if f_signature_b64:
            assert not _verify_rs256(
                f"{f_header_b64}.{f_payload_b64}".encode(), _b64url_decode(f_signature_b64), jwk,
            ), f"{label} still verifies against the published JWK, so it is not a forgery"
        else:
            assert json.loads(_b64url_decode(f_header_b64)).get("alg") == "none", (
                f"{label} was not built as an unsigned token: header is "
                f"{_b64url_decode(f_header_b64)!r}"
            )

        read_error = _rejection_response(lambda _t=forged: c.get_user(AccessToken=_t))
        read_pair = (read_error["Error"]["Code"], read_error["Error"].get("Message"))
        assert read_pair == ("NotAuthorizedException", refusal_message), (
            f"GetUser must refuse {label} with NotAuthorizedException, got "
            f"{read_pair!r} (full payload {read_error!r})"
        )
        write_error = _rejection_response(
            lambda _t=forged: c.update_user_attributes(
                AccessToken=_t, UserAttributes=[{"Name": "given_name", "Value": _FORGED_VALUE}],
            )
        )
        write_pair = (write_error["Error"]["Code"], write_error["Error"].get("Message"))
        assert write_pair == ("NotAuthorizedException", refusal_message), (
            f"UpdateUserAttributes must refuse {label} with NotAuthorizedException, got "
            f"{write_pair!r} (full payload {write_error!r})"
        )
        landed = _attribute(c, pool_id, username, "given_name")
        assert landed == _CONTROL_VALUE, (
            f"{label} mutated the profile: given_name is {landed!r}, expected the untouched "
            f"control value {_CONTROL_VALUE!r}"
        )

    # The injected claim created no membership: the group is real, the user is not in it.
    member_groups = [
        g["GroupName"]
        for g in c.admin_list_groups_for_user(UserPoolId=pool_id, Username=username)["Groups"]
    ]
    assert member_groups == [], (
        f"a forged cognito:groups claim must not create a membership; AdminListGroupsForUser "
        f"reports {member_groups} for a user that was never added to {group_name}"
    )
    # The identical call with the genuine token still succeeds, so the refusals are about the
    # forgeries and not about the operation being closed to everyone.
    second_value = f"{_CONTROL_VALUE}-2"
    c.update_user_attributes(
        AccessToken=genuine, UserAttributes=[{"Name": "given_name", "Value": second_value}],
    )
    final = _attribute(c, pool_id, username, "given_name")
    assert final == second_value, (
        f"the genuine token must still be able to write after the refusals; expected "
        f"given_name={second_value!r}, AdminGetUser reports {final!r}"
    )


# ===== helpers =====
def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _flip_one_byte(signature_b64: str) -> str:
    """Return the signature with its first byte incremented — a genuine RSA signature forgery,
    proved to be one by the local verification above rather than assumed."""
    raw = bytearray(_b64url_decode(signature_b64))
    raw[0] = (raw[0] + 1) % 256
    return _b64url_encode(bytes(raw))


def _jwk_for_kid(client, pool_id: str, kid: str | None) -> dict:
    """Fetch the pool's published JWKS and return the JWK for `kid`. The URL is derived from
    the client's endpoint_url so it follows the target (real AWS serves the regional
    cognito-idp host; an emulator its single endpoint)."""
    assert kid, "the access token header carries no kid, so no JWK can be selected"
    url = f"{client.meta.endpoint_url.rstrip('/')}/{pool_id}/.well-known/jwks.json"
    with urllib.request.urlopen(url, timeout=30) as r:  # noqa: S310 - fixed https/http scheme
        jwks = json.loads(r.read().decode())
    jwk = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    assert jwk is not None, f"kid {kid} is not present in the published JWKS {jwks}"
    return jwk


def _verify_rs256(signing_input: bytes, signature: bytes, jwk: dict) -> bool:
    """Verify an RS256 (RSASSA-PKCS1-v1_5, SHA-256) JWT signature against a JWK public key —
    pure Python, no external crypto dependency."""
    n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    em = pow(int.from_bytes(signature, "big"), e, n).to_bytes(k, "big")
    digest = hashlib.sha256(signing_input).digest()
    prefix = bytes.fromhex("3031300d060960864801650304020105000420")  # SHA-256 DigestInfo DER
    ps_len = k - len(prefix) - len(digest) - 3
    return em == b"\x00\x01" + b"\xff" * ps_len + b"\x00" + prefix + digest


def _attribute(c, pool_id: str, username: str, name: str) -> str | None:
    """Read one user attribute through AdminGetUser — a different operation, and a different
    authorization path, from the token-authorized call under test."""
    for attr in c.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]:
        if attr["Name"] == name:
            return attr["Value"]
    return None


def _rejection_response(fn) -> dict:
    """Return the full botocore error response of a call expected to be REJECTED.

    Raises when the call SUCCEEDS instead of returning a falsy sentinel: a target accepting
    a forged token is the strongest signal and must never be reported as an
    error-code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, which is the defect: {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
