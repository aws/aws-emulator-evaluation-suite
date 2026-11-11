"""signup-usersub-consistent-with-admin-get-user."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "signup-usersub-consistent-with-admin-get-user"
GROUP = 'signup-and-identity'
SERVICES = ['cognito-idp']

PASSWORD = "Str0ngPassw0rd!"
FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The UserSub returned by SignUp equals the user's "sub" attribute in AdminGetUser after
    confirmation: it is the stable identifier of the record SignUp created."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), AutoVerifiedAttributes=["email"], DeletionProtection="INACTIVE", UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), ExplicitAuthFlows=list(FLOWS), GenerateSecret=False)["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))

    username = ctx.unique_name("sim2real-behav-cip-signup-sub-")
    signup = c.sign_up(
        ClientId=client_id,
        Username=username,
        Password=PASSWORD,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}],
    )
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))
    user_sub = signup["UserSub"]
    assert user_sub, f"expected SignUp to return a non-empty UserSub, got {user_sub!r}"

    c.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)
    desc = c.admin_get_user(UserPoolId=pool_id, Username=username)
    attrs = {a["Name"]: a["Value"] for a in desc["UserAttributes"]}
    assert attrs.get("sub") == user_sub, (
        f"AdminGetUser's sub attribute {attrs.get('sub')!r} does not match "
        f"SignUp's UserSub {user_sub!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
