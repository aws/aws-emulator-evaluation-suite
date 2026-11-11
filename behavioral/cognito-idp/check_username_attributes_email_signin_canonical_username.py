"""username-attributes-email-signin-canonical-username."""
from __future__ import annotations

import base64
import json
import uuid

from behavioral_harness import tags

CHECK = "username-attributes-email-signin-canonical-username"
GROUP = 'signup-and-identity'
SERVICES = ['cognito-idp']

PASSWORD = "Sup3r-Secret-Passw0rd!"
USER_AUTH_FLOWS = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]


def _decode_jwt_segment(segment: str) -> dict:
    """base64url-decode a JWT header/payload segment into a dict (no signature verify)."""
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding))


def _is_uuid(value: str) -> bool:
    """True iff value parses as a canonical UUID string."""
    try:
        return str(uuid.UUID(value)) == value.lower()
    except (ValueError, AttributeError, TypeError):
        return False


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """With UsernameAttributes email, the Username is a generated UUID, not the email: AdminGetUser and
    ListUsers by email resolve to it, and an email sign-in issues tokens whose cognito:username and
    username claims are that UUID, as downstream authorizers correlate on it."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UsernameAttributes=["email"],
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=list(USER_AUTH_FLOWS),
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )

    described_pool = c.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    assert described_pool.get("UsernameAttributes") == ["email"], (
        f"DescribeUserPool must round-trip UsernameAttributes=['email'], got "
        f"{described_pool.get('UsernameAttributes')}"
    )

    email = f"{ctx.unique_name('sim2real-behav-cipuser')}@example.com"
    created = c.admin_create_user(
        UserPoolId=pool_id,
        Username=email,
        UserAttributes=[{"Name": "email", "Value": email}],
        MessageAction="SUPPRESS",
    )["User"]
    canonical = created["Username"]
    ctx.on_cleanup(
        lambda _p=pool_id, _u=canonical: c.admin_delete_user(UserPoolId=_p, Username=_u)
    )

    assert canonical != email, (
        "in a UsernameAttributes=['email'] pool the canonical Username must NOT be the email "
        f"address itself, got {canonical}"
    )
    assert _is_uuid(canonical), (
        f"the canonical Username must be a service-generated UUID, got {canonical!r}"
    )

    # The email resolves as an alias on the admin surface, and reports the canonical name.
    by_alias = c.admin_get_user(UserPoolId=pool_id, Username=email)
    assert by_alias["Username"] == canonical, (
        f"AdminGetUser via the email alias must report the canonical Username {canonical}, "
        f"got {by_alias['Username']}"
    )
    alias_attrs = {a["Name"]: a["Value"] for a in by_alias.get("UserAttributes", [])}
    assert alias_attrs.get("email") == email, (
        f"the email attribute must be {email}, got {alias_attrs.get('email')}"
    )
    assert alias_attrs.get("sub"), (
        f"the user must carry a sub attribute, got attributes {sorted(alias_attrs)}"
    )

    c.admin_set_user_password(
        UserPoolId=pool_id, Username=canonical, Password=PASSWORD, Permanent=True
    )

    # Sign-in happens with the ALIAS, not the canonical username.
    resp = c.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": email, "PASSWORD": PASSWORD},
    )
    assert "ChallengeName" not in resp, (
        f"unexpected challenge {resp.get('ChallengeName')} signing in by email alias"
    )
    result = resp["AuthenticationResult"]
    for field in ("AccessToken", "IdToken", "RefreshToken"):
        assert result.get(field), f"expected {field} when signing in with the email alias"

    id_claims = _decode_jwt_segment(result["IdToken"].split(".")[1])
    assert id_claims.get("cognito:username") == canonical, (
        f"the IdToken cognito:username claim must be the canonical UUID username "
        f"{canonical}, got {id_claims.get('cognito:username')}"
    )
    assert id_claims.get("email") == email, (
        f"the IdToken email claim must be {email}, got {id_claims.get('email')}"
    )
    assert id_claims.get("aud") == client_id, (
        f"the IdToken aud must be {client_id}, got {id_claims.get('aud')}"
    )
    assert id_claims.get("sub") == alias_attrs["sub"], (
        f"the IdToken sub must equal the stored sub attribute {alias_attrs['sub']}, got "
        f"{id_claims.get('sub')}"
    )

    access_claims = _decode_jwt_segment(result["AccessToken"].split(".")[1])
    assert access_claims.get("username") == canonical, (
        f"the AccessToken username claim must be the canonical UUID username {canonical}, got "
        f"{access_claims.get('username')}"
    )

    # ListUsers projects the canonical name too, so the identity is consistent everywhere.
    listed = c.list_users(UserPoolId=pool_id, Filter=f'email = "{email}"')["Users"]
    assert len(listed) == 1, f"expected exactly one user matching {email}, got {len(listed)}"
    assert listed[0]["Username"] == canonical, (
        f"ListUsers must report the canonical Username {canonical}, got {listed[0]['Username']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
