"""id-token-claims-derive-from-the-user-attribute-set."""
from __future__ import annotations

import base64
import json

from behavioral_harness import tags

CHECK = "id-token-claims-derive-from-the-user-attribute-set"
GROUP = "auth-state-machine"
SERVICES = ["cognito-idp"]

PASSWORD = "Sup3r-Secret-Passw0rd!"
FLOWS = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_TIER_BEFORE = "sim2real-gold"
_TIER_AFTER = "sim2real-platinum"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Every ID-token claim is derived from the user's stored attributes (same names and values,
    `custom:` prefix kept, email_verified as a JSON boolean), and an already-issued token stays a
    snapshot of the attributes at sign-in."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        Schema=[
            {"Name": "tier", "AttributeDataType": "String", "Mutable": True},
            {"Name": "level", "AttributeDataType": "Number", "Mutable": True},
        ],
        UserPoolTags=dict(_POOL_TAGS),
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
    email = f"{username}@example.com"
    given_name = ctx.unique_name("sim2real-given-")
    c.admin_create_user(
        UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS",
        UserAttributes=[
            {"Name": "email", "Value": email},
            {"Name": "email_verified", "Value": "true"},
            {"Name": "given_name", "Value": given_name},
            {"Name": "custom:tier", "Value": _TIER_BEFORE},
            {"Name": "custom:level", "Value": "42"},
        ],
    )
    ctx.on_cleanup(
        lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True
    )

    stored = _attributes(c, pool_id, username)
    for expected_name in ("sub", "email", "email_verified", "given_name", "custom:tier",
                          "custom:level"):
        assert expected_name in stored, (
            f"AdminGetUser must report {expected_name}, the stored attribute names are "
            f"{sorted(stored)}"
        )
    assert stored["email_verified"] == "true", (
        f"the STORED email_verified must be the string 'true' (that is what makes the token's "
        f"boolean a re-typing rather than a copy), got {stored['email_verified']!r}"
    )

    issued = c.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]
    claims = _claims(issued["IdToken"])

    # --- the mapping rule, over the whole stored set rather than a chosen few ---
    missing = sorted(name for name in stored if name not in claims)
    assert missing == [], (
        f"every stored user attribute must appear as an ID-token claim of the same name; "
        f"{missing} are stored but absent from the claims {sorted(claims)}"
    )
    for name in ("sub", "email", "given_name", "custom:tier", "custom:level"):
        assert claims[name] == stored[name], (
            f"claim {name} must equal the stored attribute value {stored[name]!r}, got "
            f"{claims[name]!r}"
        )
    assert isinstance(claims["email_verified"], bool), (
        f"the email_verified claim must be a JSON boolean, got "
        f"{type(claims['email_verified']).__name__} {claims['email_verified']!r} — a string "
        f"here means the attribute map was copied into the token unconverted"
    )
    assert claims["email_verified"] is (stored["email_verified"] == "true"), (
        f"the email_verified claim must be the boolean form of the stored string "
        f"{stored['email_verified']!r}, got {claims['email_verified']!r}"
    )
    for prefixed in ("custom:tier", "custom:level"):
        bare = prefixed.split(":", 1)[1]
        assert bare not in claims, (
            f"a custom attribute must reach the token only as {prefixed}; the token also carries "
            f"a bare {bare!r} claim with value {claims.get(bare)!r}"
        )

    # --- the token is a snapshot: updating the attribute changes only the NEXT token ---
    c.update_user_attributes(
        AccessToken=issued["AccessToken"],
        UserAttributes=[{"Name": "custom:tier", "Value": _TIER_AFTER}],
    )
    updated = _attributes(c, pool_id, username)
    assert updated["custom:tier"] == _TIER_AFTER, (
        f"the self-service update did not land: AdminGetUser reports custom:tier="
        f"{updated.get('custom:tier')!r}, expected {_TIER_AFTER!r}"
    )
    still_old = _claims(issued["IdToken"])
    assert still_old["custom:tier"] == _TIER_BEFORE, (
        f"an already-issued ID token must keep the value it was signed with; re-decoding it "
        f"reports custom:tier={still_old['custom:tier']!r} instead of {_TIER_BEFORE!r}"
    )
    reissued = c.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]["IdToken"]
    fresh = _claims(reissued)
    assert fresh["custom:tier"] == _TIER_AFTER, (
        f"a token issued after the update must carry the new value; expected custom:tier="
        f"{_TIER_AFTER!r}, got {fresh['custom:tier']!r}"
    )
    assert fresh["sub"] == stored["sub"], (
        f"the sub claim must not change when an attribute does; expected {stored['sub']!r}, got "
        f"{fresh['sub']!r}"
    )


# ===== helpers =====
def _attributes(c, pool_id: str, username: str) -> dict[str, str]:
    """The user's stored attribute set, read through AdminGetUser — a different operation from
    the sign-in that mints the token."""
    resp = c.admin_get_user(UserPoolId=pool_id, Username=username)
    return {a["Name"]: a["Value"] for a in resp["UserAttributes"]}


def _claims(token: str) -> dict:
    """base64url-decode a JWT's payload segment."""
    parts = token.split(".")
    assert len(parts) == 3, f"not a well-formed JWT (header.payload.signature): {token[:24]!r}..."
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
