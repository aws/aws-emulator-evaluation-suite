"""get-user-reflects-latest-self-service-attribute-update."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-user-reflects-latest-self-service-attribute-update"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetUser returns attributes matching the most recent self-service
    UpdateUserAttributes call, not a stale copy from an earlier value."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)
    client_id = _create_client(ctx, pool_id)
    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real!Passw0rd"
    _create_confirmed_user(
        ctx, pool_id, username, password, user_attributes=[{"Name": "family_name", "Value": "OriginalName"}]
    )
    access_token = _admin_password_auth(ctx, pool_id, client_id, username, password)["AccessToken"]

    before = idp.get_user(AccessToken=access_token)
    before_attrs = {a["Name"]: a["Value"] for a in before["UserAttributes"]}
    assert before_attrs["family_name"] == "OriginalName", (
        f"expected pre-update family_name 'OriginalName', got {before_attrs.get('family_name')!r}"
    )

    idp.update_user_attributes(AccessToken=access_token, UserAttributes=[{"Name": "family_name", "Value": "UpdatedName"}])

    after = idp.get_user(AccessToken=access_token)
    after_attrs = {a["Name"]: a["Value"] for a in after["UserAttributes"]}
    assert after_attrs["family_name"] == "UpdatedName", (
        f"expected post-update family_name 'UpdatedName', got {after_attrs.get('family_name')!r}"
    )

    idp.update_user_attributes(AccessToken=access_token, UserAttributes=[{"Name": "family_name", "Value": "SecondUpdateName"}])
    second = idp.get_user(AccessToken=access_token)
    second_attrs = {a["Name"]: a["Value"] for a in second["UserAttributes"]}
    assert second_attrs["family_name"] == "SecondUpdateName", (
        f"expected family_name to reflect the second self-service update "
        f"'SecondUpdateName', got {second_attrs.get('family_name')!r} "
        f"(a one-update-behind cache would still show 'UpdatedName')"
    )

    idp.delete_user_pool(UserPoolId=pool_id)
    code, message = _error(lambda: idp.describe_user_pool(UserPoolId=pool_id))
    assert code == "ResourceNotFoundException", (
        f"expected DescribeUserPool on a deleted pool to fail with ResourceNotFoundException, got {code}"
    )
    expected = f"User pool {pool_id} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_user_pool(ctx, **kwargs):
    idp = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-pool-")
    kwargs.setdefault("UserPoolTags", {"sim2real:managed": "true", "sim2real:prefix": "sim2real"})
    # Explicit rather than relying on Cognito's account-level default, so cleanup's DeleteUserPool
    # is never blocked by deletion protection.
    kwargs.setdefault("DeletionProtection", "INACTIVE")
    resp = idp.create_user_pool(PoolName=name, **kwargs)
    pool_id = resp["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_pool_if_present(idp, pool_id))
    return pool_id


def _delete_pool_if_present(idp, pool_id):
    """Teardown: the check deletes its pool itself, so an already-deleted pool is the expected state."""
    try:
        idp.delete_user_pool(UserPoolId=pool_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_client(ctx, pool_id, **kwargs):
    idp = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-client-")
    kwargs.setdefault("ExplicitAuthFlows", ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"])
    resp = idp.create_user_pool_client(UserPoolId=pool_id, ClientName=name, GenerateSecret=False, **kwargs)
    return resp["UserPoolClient"]["ClientId"]


def _create_confirmed_user(ctx, pool_id, username, password, user_attributes=None):
    idp = ctx.client("cognito-idp")
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
        UserAttributes=user_attributes or [],
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)


def _admin_password_auth(ctx, pool_id, client_id, username, password):
    idp = ctx.client("cognito-idp")
    resp = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return resp["AuthenticationResult"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
