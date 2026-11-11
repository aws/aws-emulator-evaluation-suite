"""id-token-and-m2m-token-are-refused-where-a-user-access-token-is-required."""
from __future__ import annotations

import base64
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "id-token-and-m2m-token-are-refused-where-a-user-access-token-is-required"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]

PASSWORD = "Sup3r-Secret-Passw0rd!"
USER_FLOWS = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_USER_POOL_SCOPE = "aws.cognito.signin.user.admin"
_CONTROL_VALUE = "sim2real-control-value"
_FORGED_VALUE = "sim2real-value-that-must-never-land"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetUser and UpdateUserAttributes accept only a user access token: the ID token and a
    client_credentials token (no user, no aws.cognito.signin.user.admin scope) are refused
    with NotAuthorizedException and leave the profile unchanged.
    """
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags=dict(_POOL_TAGS),
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _p=pool_id: c.delete_user_pool(UserPoolId=_p))

    user_client_id = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=list(USER_FLOWS), GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=user_client_id: c.delete_user_pool_client(
            UserPoolId=_p, ClientId=_c
        )
    )

    resource_server_id = ctx.unique_name("sim2real-behav-rs")
    c.create_resource_server(
        UserPoolId=pool_id, Identifier=resource_server_id, Name="sim2real behav resource server",
        Scopes=[{"ScopeName": "read", "ScopeDescription": "read access"}],
    )
    m2m = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-m2m-client-"),
        GenerateSecret=True, ExplicitAuthFlows=["ALLOW_CLIENT_TOKEN_AUTH"],
        AllowedOAuthFlows=["client_credentials"], AllowedOAuthFlowsUserPoolClient=True,
        AllowedOAuthScopes=[f"{resource_server_id}/read"],
    )["UserPoolClient"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=m2m["ClientId"]: c.delete_user_pool_client(
            UserPoolId=_p, ClientId=_c
        )
    )

    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(
        lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True
    )

    issued = c.initiate_auth(
        ClientId=user_client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]
    access_token, id_token = issued["AccessToken"], issued["IdToken"]
    m2m_token = c.get_client_token(
        ClientId=m2m["ClientId"], Secret=m2m["ClientSecret"],
        Scopes=[f"{resource_server_id}/read"],
    )["ClientAuthenticationResult"]["AccessToken"]

    # --- what makes the three tokens different, stated from their own claims ---
    access_claims, id_claims, m2m_claims = (
        _claims(access_token), _claims(id_token), _claims(m2m_token)
    )
    assert access_claims.get("token_use") == "access", (
        f"the user token must be token_use=access, got {access_claims.get('token_use')!r}"
    )
    assert _USER_POOL_SCOPE in (access_claims.get("scope") or "").split(), (
        f"the user access token must carry the {_USER_POOL_SCOPE} scope that authorizes "
        f"token-based user-pool operations, got scope={access_claims.get('scope')!r}"
    )
    assert id_claims.get("token_use") == "id", (
        f"the ID token must be token_use=id, got {id_claims.get('token_use')!r}"
    )
    assert m2m_claims.get("token_use") == "access", (
        f"the client_credentials token must be token_use=access, got "
        f"{m2m_claims.get('token_use')!r}"
    )
    assert m2m_claims.get("scope") == f"{resource_server_id}/read", (
        f"the client_credentials token must be scoped to exactly the requested resource-server "
        f"scope {resource_server_id}/read, got {m2m_claims.get('scope')!r}"
    )
    assert _USER_POOL_SCOPE not in (m2m_claims.get("scope") or "").split(), (
        f"a client_credentials token must not carry {_USER_POOL_SCOPE}, got scope="
        f"{m2m_claims.get('scope')!r}"
    )
    assert "username" not in m2m_claims, (
        f"a client_credentials token has no user, so it must carry no username claim; claims "
        f"were {sorted(m2m_claims)}"
    )

    # --- positive control: the user access token both reads AND writes the profile ---
    me = c.get_user(AccessToken=access_token)
    assert me["Username"] == username, (
        f"the user access token must identify {username} at GetUser, got "
        f"{me.get('Username')!r}"
    )
    c.update_user_attributes(
        AccessToken=access_token, UserAttributes=[{"Name": "given_name", "Value": _CONTROL_VALUE}],
    )
    control_landed = _attribute(c, pool_id, username, "given_name")
    assert control_landed == _CONTROL_VALUE, (
        f"the control write did not land: expected given_name={_CONTROL_VALUE!r}, "
        f"AdminGetUser reports {control_landed!r}"
    )

    # --- break exactly one thing at a time: the token, and nothing else ---
    for label, token, expected_message in (
        ("the ID token from the same sign-in", id_token, "Invalid Access Token"),
        ("a client_credentials access token with no user", m2m_token, "Access Token does not have required scopes"),
    ):
        read_error = _rejection_response(lambda _t=token: c.get_user(AccessToken=_t))
        assert read_error["Error"]["Code"] == "NotAuthorizedException", (
            f"GetUser must refuse {label} with NotAuthorizedException, got "
            f"{read_error['Error']['Code']!r} (full payload {read_error!r})"
        )
        assert read_error["Error"].get("Message") == expected_message, (
            f"GetUser must refuse {label} with message {expected_message!r}, got "
            f"{read_error['Error'].get('Message')!r}"
        )
        write_error = _rejection_response(
            lambda _t=token: c.update_user_attributes(
                AccessToken=_t, UserAttributes=[{"Name": "given_name", "Value": _FORGED_VALUE}],
            )
        )
        assert write_error["Error"]["Code"] == "NotAuthorizedException", (
            f"UpdateUserAttributes must refuse {label} with NotAuthorizedException, got "
            f"{write_error['Error']['Code']!r} (full payload {write_error!r})"
        )
        assert write_error["Error"].get("Message") == expected_message, (
            f"UpdateUserAttributes must refuse {label} with message {expected_message!r}, got "
            f"{write_error['Error'].get('Message')!r}"
        )
        # the effect is absent, read independently through an admin operation
        landed = _attribute(c, pool_id, username, "given_name")
        assert landed == _CONTROL_VALUE, (
            f"{label} mutated the profile: given_name is {landed!r}, expected the untouched "
            f"control value {_CONTROL_VALUE!r}"
        )

    # --- the identical call with the right token still succeeds, so the refusals above are
    # about the token and not about the operation being broken for everyone.
    second_value = f"{_CONTROL_VALUE}-2"
    c.update_user_attributes(
        AccessToken=access_token, UserAttributes=[{"Name": "given_name", "Value": second_value}],
    )
    final = _attribute(c, pool_id, username, "given_name")
    assert final == second_value, (
        f"the user access token must still be able to write after the refusals; expected "
        f"given_name={second_value!r}, AdminGetUser reports {final!r}"
    )


def _claims(token: str) -> dict:
    """Decode a JWT's payload segment without verifying the signature."""
    parts = token.split(".")
    assert len(parts) == 3, f"not a well-formed JWT (header.payload.signature): {token[:24]!r}..."
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def _attribute(c, pool_id: str, username: str, name: str) -> str | None:
    """Read one user attribute through AdminGetUser, an IAM-authorized path independent of the
    token under test."""
    for attr in c.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]:
        if attr["Name"] == name:
            return attr["Value"]
    return None


def _rejection_response(fn) -> dict:
    """Return the full error response of a call expected to be rejected; raise if it succeeds."""
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
