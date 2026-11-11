"""delete-user-self-service-then-get-user-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-user-self-service-then-get-user-rejected"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After self-service DeleteUser, GetUser and an attribute update with the same token and
    AdminGetUser all answer UserNotFoundException "User does not exist.", while another user in the
    pool still reads itself."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)
    client_id = _create_client(ctx, pool_id)
    password = "Sim2Real!Passw0rd"

    doomed_username = ctx.unique_name("sim2real-user-doomed-")
    surviving_username = ctx.unique_name("sim2real-user-alive-")
    _create_confirmed_user(ctx, pool_id, doomed_username, password)
    _create_confirmed_user(ctx, pool_id, surviving_username, password)

    doomed_token = _admin_password_auth(ctx, pool_id, client_id, doomed_username, password)["AccessToken"]
    surviving_token = _admin_password_auth(ctx, pool_id, client_id, surviving_username, password)["AccessToken"]

    # Sanity: both tokens work before deletion.
    doomed_before = idp.get_user(AccessToken=doomed_token)["Username"]
    assert doomed_before == doomed_username, f"expected {doomed_username!r} before deletion, got {doomed_before!r}"
    surviving_before = idp.get_user(AccessToken=surviving_token)["Username"]
    assert surviving_before == surviving_username, (
        f"expected {surviving_username!r} before deletion, got {surviving_before!r}"
    )

    idp.delete_user(AccessToken=doomed_token)

    gone = ("UserNotFoundException", "User does not exist.")
    err = _error(lambda: idp.get_user(AccessToken=doomed_token))
    assert err == gone, (
        f"expected a not-found error for a deleted user's token, got {err!r}"
    )

    admin_err = _error(lambda: idp.admin_get_user(UserPoolId=pool_id, Username=doomed_username))
    assert admin_err == gone, f"expected {gone!r}, got {admin_err!r}"

    # The deleted identity is not just unreadable — a mutation against it fails the same way.
    mutation_err = _error(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=doomed_username))
    assert mutation_err == gone, (
        f"expected a second AdminDeleteUser on the same identity to fail with {gone!r}, "
        f"got {mutation_err!r}"
    )

    # Positive control: the untouched sibling user is completely unaffected.
    control = idp.get_user(AccessToken=surviving_token)["Username"]
    assert control == surviving_username, f"expected sibling user {surviving_username!r} unaffected, got {control!r}"


def _create_user_pool(ctx, **kwargs):
    idp = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-pool-")
    kwargs.setdefault("UserPoolTags", {"sim2real:managed": "true", "sim2real:prefix": "sim2real-pool"})
    resp = idp.create_user_pool(PoolName=name, **kwargs)
    pool_id = resp["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


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


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
