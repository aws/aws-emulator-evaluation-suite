"""self-service-delete-user-removes-attributes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "self-service-delete-user-removes-attributes"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteUserAttributes removes a named attribute from the profile, and DeleteUser
    transitions the account itself to a fully removed state."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-pool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-user-")
    password = "Str0ng!Passw0rd"
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[
            {"Name": "email", "Value": f"{username}@example.com"},
            {"Name": "email_verified", "Value": "true"},
            {"Name": "nickname", "Value": "Buddy"},
        ],
        MessageAction="SUPPRESS",
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    access_token = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]["AccessToken"]

    before = {a["Name"]: a["Value"] for a in idp.get_user(AccessToken=access_token)["UserAttributes"]}
    assert before.get("nickname") == "Buddy", f"expected pre-delete nickname 'Buddy', got {before.get('nickname')!r}"

    idp.delete_user_attributes(AccessToken=access_token, UserAttributeNames=["nickname"])

    after = {a["Name"]: a["Value"] for a in idp.get_user(AccessToken=access_token)["UserAttributes"]}
    assert "nickname" not in after, f"expected nickname removed by DeleteUserAttributes, still present: {after!r}"

    idp.delete_user(AccessToken=access_token)

    # On real AWS the access token remains cryptographically valid (it isn't
    # instantly revoked), so GetUser proceeds to look up the backing user
    # record; since it no longer exists, Cognito raises UserNotFoundException
    # rather than NotAuthorizedException.
    get_user_code, get_user_message = _rejection(lambda: idp.get_user(AccessToken=access_token))
    assert get_user_code == "UserNotFoundException", (
        f"expected UserNotFoundException from GetUser on a deleted user's token, got {get_user_code!r}"
    )
    assert get_user_message == "User does not exist.", f"expected message 'User does not exist.', got {get_user_message!r}"
    admin_get_user_code, admin_get_user_message = _rejection(
        lambda: idp.admin_get_user(UserPoolId=pool_id, Username=username)
    )
    assert admin_get_user_code == "UserNotFoundException", (
        f"expected UserNotFoundException from AdminGetUser after self-service DeleteUser, got {admin_get_user_code!r}"
    )
    assert admin_get_user_message == "User does not exist.", (
        f"expected message 'User does not exist.', got {admin_get_user_message!r}"
    )

    # The dead identity is unusable for mutation too, not just for reads.
    admin_disable_code, admin_disable_message = _rejection(
        lambda: idp.admin_disable_user(UserPoolId=pool_id, Username=username)
    )
    assert admin_disable_code == "UserNotFoundException", (
        f"expected UserNotFoundException from AdminDisableUser on a deleted user, got {admin_disable_code!r}"
    )
    assert admin_disable_message == "User does not exist.", (
        f"expected message 'User does not exist.', got {admin_disable_message!r}"
    )


def _rejection(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
