"""list-users-invalid-filter-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-users-invalid-filter-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

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
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError("expected a ClientError, but the call succeeded")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListUsers with a Filter on an attribute that does not support filtering is rejected with
    InvalidParameterException rather than returning an empty or unfiltered result."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags=_TAGS,
        Policies=_LENIENT_POLICY,
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))

    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="Sim2Real8!",
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))

    # Positive control: a supported filter attribute works, so filtering is not broadly broken.
    positive = c.list_users(UserPoolId=pool_id, Filter=f'username = "{username}"')["Users"]
    assert any(u["Username"] == username for u in positive), (
        f"expected {username} via a valid username filter, got {positive}"
    )

    # nickname is a real standard attribute but not in ListUsers' searchable-attribute set.
    code, message = _error(
        lambda: c.list_users(UserPoolId=pool_id, Filter='nickname = "whatever"')
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected = "Input fails to satisfy the constraints."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
