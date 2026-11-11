"""list-users-invalid-limit-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-users-invalid-limit-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: ListUsers with a Limit above the documented max (60) MUST fail."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))

    username = ctx.unique_name("sim2real-behav-user-")
    c.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="TempPassw0rd!",
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda _u=username: c.admin_delete_user(UserPoolId=pool_id, Username=_u))

    # Positive control: ListUsers at the documented max (60) must succeed and see the
    # user we just created, so a later InvalidParameterException is distinguishable from
    # "this target rejects every ListUsers call".
    positive = c.list_users(UserPoolId=pool_id, Limit=60)["Users"]
    assert any(u["Username"] == username for u in positive), (
        f"positive control failed: expected {username!r} in ListUsers(Limit=60) result, got {positive}"
    )

    code, message = _error(lambda: c.list_users(UserPoolId=pool_id, Limit=61))
    assert code == "InvalidParameterException", (
        f"expected ListUsers with Limit=61 to fail with InvalidParameterException, got {code}"
    )
    expected = (
        "1 validation error detected: Value '61' at 'limit' failed to satisfy constraint:"
        " Member must have value less than or equal to 60"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
