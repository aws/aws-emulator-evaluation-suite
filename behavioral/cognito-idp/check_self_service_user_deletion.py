"""self-service-user-deletion."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "self-service-user-deletion"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteUserAttributes removes specific attributes for the authenticated user, and
    DeleteUser terminates the account so a subsequent GetUser with the same access token
    fails with UserNotFoundException."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-selfdel-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-selfdel"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-selfdel-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-selfdel-user-")
    password = "Sim2Real-Pw!23456"
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[
            {"Name": "email", "Value": f"{username}@example.com"},
            {"Name": "email_verified", "Value": "true"},
            {"Name": "given_name", "Value": "Original"},
        ],
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    access_token = idp.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]["AccessToken"]

    before = idp.get_user(AccessToken=access_token)["UserAttributes"]
    assert any(a["Name"] == "given_name" and a["Value"] == "Original" for a in before), (
        f"expected given_name=Original before deletion, got {before}"
    )

    idp.delete_user_attributes(AccessToken=access_token, UserAttributeNames=["given_name"])
    after_delete_attr = idp.get_user(AccessToken=access_token)["UserAttributes"]
    assert all(a["Name"] != "given_name" for a in after_delete_attr), (
        f"expected given_name removed, still present in {after_delete_attr}"
    )
    assert any(a["Name"] == "email" for a in after_delete_attr), (
        f"expected unrelated attributes (email) to survive DeleteUserAttributes, got {after_delete_attr}"
    )

    idp.delete_user(AccessToken=access_token)
    code, message = _error(lambda: idp.get_user(AccessToken=access_token))
    assert code == "UserNotFoundException", code
    expected_message = "User does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect is real: the user no longer exists in the pool
    admin_code, admin_message = _error(lambda: idp.admin_get_user(UserPoolId=pool_id, Username=username))
    assert admin_code == "UserNotFoundException", admin_code
    expected_admin_message = "User does not exist."
    assert admin_message == expected_admin_message, f"expected message {expected_admin_message!r}, got {admin_message!r}"

    # a mutation on the dead identity is rejected the same way reads of it are, not silently accepted
    admin_mutate_code, admin_mutate_message = _error(lambda: idp.admin_disable_user(UserPoolId=pool_id, Username=username))
    assert admin_mutate_code == "UserNotFoundException", admin_mutate_code
    expected_admin_mutate_message = "User does not exist."
    assert admin_mutate_message == expected_admin_mutate_message, f"expected message {expected_admin_mutate_message!r}, got {admin_mutate_message!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
