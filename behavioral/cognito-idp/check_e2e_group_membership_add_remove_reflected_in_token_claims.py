"""e2e-group-membership-add-remove-reflected-in-token-claims."""
from __future__ import annotations

import base64
import json

from behavioral_harness import tags

CHECK = "e2e-group-membership-add-remove-reflected-in-token-claims"
GROUP = "e2e"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateGroup + AdminAddUserToGroup makes cognito:groups appear on a freshly-issued
    access token; AdminRemoveUserFromGroup makes a subsequently-issued token omit it."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-group-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-group-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-behav-group-user-")
    password = "Sim2Real!Behav123"
    idp.admin_create_user(UserPoolId=pool_id, Username=username, TemporaryPassword=password, MessageAction="SUPPRESS")
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))

    group_name = ctx.unique_name("sim2real-behav-group-")
    idp.create_group(UserPoolId=pool_id, GroupName=group_name)
    ctx.on_cleanup(lambda: idp.delete_group(UserPoolId=pool_id, GroupName=group_name))

    idp.admin_add_user_to_group(UserPoolId=pool_id, Username=username, GroupName=group_name)

    auth_in_group = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    claims_in_group = _decode_jwt_claims(auth_in_group["AuthenticationResult"]["AccessToken"])
    groups_in_group = claims_in_group.get("cognito:groups", [])
    assert group_name in groups_in_group, f"expected {group_name} in cognito:groups claim, got {groups_in_group}"

    idp.admin_remove_user_from_group(UserPoolId=pool_id, Username=username, GroupName=group_name)

    auth_after_removal = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    claims_after_removal = _decode_jwt_claims(auth_after_removal["AuthenticationResult"]["AccessToken"])
    groups_after_removal = claims_after_removal.get("cognito:groups", [])
    assert group_name not in groups_after_removal, (
        f"expected {group_name} absent from cognito:groups claim after removal, got {groups_after_removal}"
    )


def _decode_jwt_claims(jwt: str) -> dict:
    payload_segment = jwt.split(".")[1]
    padded = payload_segment + "=" * (-len(payload_segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
