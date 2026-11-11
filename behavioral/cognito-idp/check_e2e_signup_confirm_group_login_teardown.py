"""e2e-signup-confirm-group-login-teardown."""
from __future__ import annotations

import base64
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-signup-confirm-group-login-teardown"
GROUP = "e2e"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SignUp -> AdminConfirmSignUp -> AdminAddUserToGroup puts the group in the ID token's
    cognito:groups claim; after AdminDeleteUser both AdminGetUser and a login with the same
    credentials fail with UserNotFoundException."""
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-cog-e2e-"),
        DeletionProtection="INACTIVE",
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-cog-e2e"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-cog-e2e-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-cog-e2e-user-")
    password = "Str0ng!Passw0rd789"
    cognito.sign_up(ClientId=client_id, Username=username, Password=password)
    cognito.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)

    group_name = ctx.unique_name("sim2real-cog-e2e-group-")
    cognito.create_group(UserPoolId=pool_id, GroupName=group_name)
    cognito.admin_add_user_to_group(UserPoolId=pool_id, Username=username, GroupName=group_name)

    auth = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    id_token = auth["AuthenticationResult"]["IdToken"]
    claims = _decode_jwt_payload(id_token)
    assert group_name in claims.get("cognito:groups", []), (
        f"expected {group_name!r} in ID token cognito:groups claim, got {claims.get('cognito:groups')!r}"
    )

    got = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert got["Username"] == username, f"expected AdminGetUser to echo {username!r}, got {got['Username']!r}"

    cognito.admin_delete_user(UserPoolId=pool_id, Username=username)

    get_code, get_message = _error(lambda: cognito.admin_get_user(UserPoolId=pool_id, Username=username))
    assert get_code == "UserNotFoundException", f"expected UserNotFoundException, got {get_code!r}"
    assert get_message == "User does not exist.", (
        f"expected the exact UserNotFoundException message 'User does not exist.', got {get_message!r}"
    )

    # Deletion is not just invisible to a read; it makes the account unusable for login too.
    login_code, login_message = _error(
        lambda: cognito.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )
    )
    assert login_code == "UserNotFoundException", f"expected UserNotFoundException, got {login_code!r}"
    assert login_message == "User does not exist.", (
        f"expected the exact UserNotFoundException message 'User does not exist.', got {login_message!r}"
    )


def _decode_jwt_payload(token: str) -> dict:
    payload_b64 = token.split(".")[1]
    padding = "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64 + padding))


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    a target that accepts a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
