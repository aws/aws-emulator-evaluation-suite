"""list-users-attributes-to-get-requires-a-value-on-every-user."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-users-attributes-to-get-requires-a-value-on-every-user"
GROUP = "search-and-filtering"
SERVICES = ["cognito-idp"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_LENIENT_POLICY = {
    "PasswordPolicy": {
        "MinimumLength": 8,
        "RequireUppercase": False,
        "RequireLowercase": False,
        "RequireNumbers": False,
        "RequireSymbols": False,
    }
}


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListUsers(AttributesToGet=[...]) projects every user to only the named attributes, and
    refuses the whole call when any matched user has not set a value for one of them."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-latg-pool-"),
        UserPoolTags=_TAGS,
        Policies=_LENIENT_POLICY,
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    user_a = ctx.unique_name("sim2real-behav-latg-a-")
    user_b = ctx.unique_name("sim2real-behav-latg-b-")
    idp.admin_create_user(
        UserPoolId=pool_id, Username=user_a, MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "given_name", "Value": "Jane"}],
    )
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=user_a))
    idp.admin_create_user(UserPoolId=pool_id, Username=user_b, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=user_b))

    # Positive control: an unprojected listing returns every created user with its full attributes.
    full = idp.list_users(UserPoolId=pool_id)["Users"]
    full_names = {u["Username"] for u in full}
    assert {user_a, user_b} <= full_names, f"expected {user_a!r} and {user_b!r} in {full_names!r}"
    a_full = next(u for u in full if u["Username"] == user_a)
    a_given_name = {a["Name"]: a["Value"] for a in a_full["Attributes"]}.get("given_name")
    assert a_given_name == "Jane", f"expected given_name 'Jane' on {user_a!r}, got {a_given_name!r}"

    # Break exactly one thing: user_b has no given_name, so projecting on it must be refused.
    code, message = _error(
        lambda: idp.list_users(UserPoolId=pool_id, AttributesToGet=["given_name"])
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}: {message!r}"
    want = "Input fails to satisfy the constraints."
    assert message == want, f"expected message {want!r}, got {message!r}"

    # Restore: once every matched user has a value, the identical call succeeds and projects.
    idp.admin_update_user_attributes(
        UserPoolId=pool_id, Username=user_b, UserAttributes=[{"Name": "given_name", "Value": "Doe"}],
    )
    projected = idp.list_users(UserPoolId=pool_id, AttributesToGet=["given_name"])["Users"]
    by_name = {u["Username"]: {a["Name"]: a["Value"] for a in u["Attributes"]} for u in projected}
    assert set(by_name) == {user_a, user_b}, f"expected exactly {{{user_a!r}, {user_b!r}}}, got {set(by_name)!r}"
    assert by_name[user_a] == {"given_name": "Jane"}, (
        f"expected {user_a!r} projected to only given_name='Jane', got {by_name[user_a]!r}"
    )
    assert by_name[user_b] == {"given_name": "Doe"}, (
        f"expected {user_b!r} projected to only given_name='Doe', got {by_name[user_b]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
