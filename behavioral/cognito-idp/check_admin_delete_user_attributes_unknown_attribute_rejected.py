"""admin-delete-user-attributes-unknown-attribute-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-delete-user-attributes-unknown-attribute-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

_LENIENT_PASSWORD_POLICY = {
    "PasswordPolicy": {
        "MinimumLength": 8,
        "RequireUppercase": False,
        "RequireLowercase": False,
        "RequireNumbers": False,
        "RequireSymbols": False,
    }
}
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
PASSWORD = "Str0ngPassw0rd!"


def _new_pool(ctx, c, **kwargs):
    kwargs.setdefault("Policies", _LENIENT_PASSWORD_POLICY)
    kwargs.setdefault("UserPoolTags", _POOL_TAGS)
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), **kwargs
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _new_confirmed_user(ctx, c, pool_id, **extra_attrs):
    username = ctx.unique_name("sim2real-behav-cip-user-")
    attrs = [{"Name": "email", "Value": f"{username}@example.com"}]
    attrs.extend({"Name": k, "Value": v} for k, v in extra_attrs.items())
    c.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="Temp0rar1Pass!",
        MessageAction="SUPPRESS",
        UserAttributes=attrs,
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True)
    return username, PASSWORD


def _attrs(c, pool_id, username):
    return {
        a["Name"]: a["Value"]
        for a in c.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AdminDeleteUserAttributes for an attribute the pool schema never defined is refused with
    InvalidParameterException and the exact message and changes nothing, while deleting a defined
    attribute (nickname) removes it."""
    c = ctx.client("cognito-idp")
    pool_id = _new_pool(ctx, c)
    username, _password = _new_confirmed_user(ctx, c, pool_id, nickname="Buddy")

    before = _attrs(c, pool_id, username)
    assert before.get("nickname") == "Buddy", f"expected nickname='Buddy' before delete, got {before.get('nickname')!r}"

    # Positive control: a real, schema-defined attribute is genuinely deletable here.
    c.admin_delete_user_attributes(UserPoolId=pool_id, Username=username, UserAttributeNames=["nickname"])
    after_control = _attrs(c, pool_id, username)
    assert "nickname" not in after_control, "positive control: AdminDeleteUserAttributes did not remove a real attribute"

    code, message = _error(
        lambda: c.admin_delete_user_attributes(
            UserPoolId=pool_id,
            Username=username,
            UserAttributeNames=["custom:never_defined_attr"],
        )
    )
    assert (code, message) == ("InvalidParameterException", "Invalid user attributes: Type for attribute {custom:never_defined_attr} could not be determined"), f"expected InvalidParameterException, got {(code, message)!r}"

    after_rejected = _attrs(c, pool_id, username)
    assert after_rejected.get("email") == f"{username}@example.com", "unrelated attribute must survive the rejected call"
    assert "nickname" not in after_rejected, "the rejected call must not resurrect or otherwise touch state"


def _error(fn):
    """Call fn(); return its (code, message). A call that succeeds raises: a target that
    accepts what AWS refuses must fail loudly, never as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
