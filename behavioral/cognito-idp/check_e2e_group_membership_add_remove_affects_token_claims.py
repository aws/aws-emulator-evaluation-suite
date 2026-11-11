"""e2e-group-membership-add-remove-affects-token-claims."""
from __future__ import annotations

import base64
import json

from behavioral_harness import tags

CHECK = "e2e-group-membership-add-remove-affects-token-claims"
GROUP = "e2e"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """AdminAddUserToGroup puts the group in the next login's ID token cognito:groups claim and
    AdminRemoveUserFromGroup removes it from the login after that."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-groupclaims-pool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
            }
        },
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-groupclaims-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]

    group_name = ctx.unique_name("sim2real-group-")
    cognito.create_group(GroupName=group_name, UserPoolId=pool_id, Description="behavioral check")
    ctx.on_cleanup(lambda: cognito.delete_group(GroupName=group_name, UserPoolId=pool_id))

    username = ctx.unique_name("s2rgroupuser")
    password = "Str0ngPassw0rd!"
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}],
        MessageAction="SUPPRESS",
    )
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )

    def _login_group_claims() -> list[str]:
        auth = cognito.admin_initiate_auth(
            UserPoolId=pool_id,
            ClientId=client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )
        id_token = auth["AuthenticationResult"]["IdToken"]
        claims = _decode_jwt_claims(id_token)
        return list(claims.get("cognito:groups", []))

    before = _login_group_claims()
    assert group_name not in before, (
        f"expected no cognito:groups claim for {group_name} before AdminAddUserToGroup, got {before}"
    )

    cognito.admin_add_user_to_group(UserPoolId=pool_id, Username=username, GroupName=group_name)
    during = _login_group_claims()
    assert group_name in during, (
        f"expected cognito:groups to contain {group_name} on the login after AdminAddUserToGroup, got {during}"
    )

    cognito.admin_remove_user_from_group(
        UserPoolId=pool_id, Username=username, GroupName=group_name
    )
    after = _login_group_claims()
    assert group_name not in after, (
        f"expected cognito:groups to omit {group_name} on the login after AdminRemoveUserFromGroup, got {after}"
    )


def _decode_jwt_claims(token: str) -> dict:
    payload_b64 = token.split(".")[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
