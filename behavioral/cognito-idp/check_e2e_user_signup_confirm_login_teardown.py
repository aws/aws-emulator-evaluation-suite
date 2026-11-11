"""e2e-user-signup-confirm-login-teardown."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "e2e-user-signup-confirm-login-teardown"
GROUP = "e2e"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An unconfirmed user cannot sign in (UserNotConfirmedException), confirming allows login,
    and after DeleteUser the login, AdminGetUser and attribute updates fail with
    UserNotFoundException."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-signup-pool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
            }
        },
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-signup"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-signup-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("s2ruser")
    password = "Str0ngPassw0rd!"

    signup = cognito.sign_up(
        ClientId=client_id,
        Username=username,
        Password=password,
    )
    assert signup["UserConfirmed"] is False, (
        f"expected UserConfirmed False right after SignUp, got {signup['UserConfirmed']!r}"
    )

    status = cognito.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status == "UNCONFIRMED", f"expected UserStatus UNCONFIRMED after SignUp, got {status!r}"

    pre_confirm_code, pre_confirm_status, pre_confirm_message = _error(
        lambda: cognito.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )
    )
    assert pre_confirm_code == "UserNotConfirmedException" and isinstance(pre_confirm_status, int) and 400 <= pre_confirm_status < 500 and pre_confirm_message, (
        f"expected (UserNotConfirmedException, 4xx) for an unconfirmed user's login, got {(pre_confirm_code, pre_confirm_status, pre_confirm_message)!r}"
    )
    expected_message = "User is not confirmed."
    assert pre_confirm_message == expected_message, f"expected the message {expected_message!r}, got {pre_confirm_message!r}"

    # The ConfirmSignUp code is only delivered by email/SMS, so use the admin bypass.
    cognito.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)
    status = cognito.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status == "CONFIRMED", f"expected UserStatus CONFIRMED after AdminConfirmSignUp, got {status!r}"

    auth = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = auth["AuthenticationResult"]["AccessToken"]

    who = cognito.get_user(AccessToken=access_token)
    assert who["Username"] == username, f"expected GetUser to resolve {username!r}, got {who['Username']!r}"

    listed = _list_usernames(cognito, pool_id, username)
    assert listed == [username], f"expected ListUsers filtered to the user to return [{username!r}], got {listed!r}"

    cognito.delete_user(AccessToken=access_token)

    post_delete_code, post_delete_status, post_delete_message = _error(
        lambda: cognito.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )
    )
    assert post_delete_code == "UserNotFoundException" and isinstance(post_delete_status, int) and 400 <= post_delete_status < 500 and post_delete_message, (
        f"expected (UserNotFoundException, 4xx) for a login after DeleteUser, got {(post_delete_code, post_delete_status, post_delete_message)!r}"
    )
    expected_message = "User does not exist."
    assert post_delete_message == expected_message, f"expected the message {expected_message!r}, got {post_delete_message!r}"

    admin_get_code, admin_get_status, admin_get_message = _error(
        lambda: cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    )
    assert admin_get_code == "UserNotFoundException" and isinstance(admin_get_status, int) and 400 <= admin_get_status < 500 and admin_get_message, (
        f"expected (UserNotFoundException, 4xx) from AdminGetUser after DeleteUser, got {(admin_get_code, admin_get_status, admin_get_message)!r}"
    )
    expected_message = "User does not exist."
    assert admin_get_message == expected_message, f"expected the message {expected_message!r}, got {admin_get_message!r}"

    listed = _list_usernames(cognito, pool_id, username)
    assert listed == [], f"expected ListUsers filtered to the deleted user to return [], got {listed!r}"

    dead_update_code, dead_update_status, dead_update_message = _error(
        lambda: cognito.admin_update_user_attributes(
            UserPoolId=pool_id,
            Username=username,
            UserAttributes=[{"Name": "name", "Value": "dead"}],
        )
    )
    assert dead_update_code == "UserNotFoundException" and isinstance(dead_update_status, int) and 400 <= dead_update_status < 500, (
        f"expected (UserNotFoundException, 4xx) from AdminUpdateUserAttributes on the deleted user, got {(dead_update_code, dead_update_status, dead_update_message)!r}"
    )
    expected_message = "User does not exist."
    assert dead_update_message == expected_message, f"expected the message {expected_message!r}, got {dead_update_message!r}"


def _error(fn):
    """Call fn(); return its botocore (Code, HTTP status, Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _list_usernames(client, pool_id: str, username: str) -> list[str]:
    """Usernames ListUsers returns for an exact username filter, across all pages."""
    names: list[str] = []
    for page in client.get_paginator("list_users").paginate(
        UserPoolId=pool_id, Filter=f'username = "{username}"'
    ):
        names.extend(u["Username"] for u in page["Users"])
    return names


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
