"""op-contract-adminUpdateUserAttributes."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-adminUpdateUserAttributes"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminUpdateUserAttributes writes a nickname, and setting an email another user holds verified moves
    it to the new user as verified and leaves the previous holder's email_verified false."""
    cognito = ctx.client("cognito-idp")
    pool = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        AliasAttributes=["email"],
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-pool"},
    )["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    user_a = ctx.unique_name("sim2real-user-a-")
    user_b = ctx.unique_name("sim2real-user-b-")
    shared_email = f"{ctx.unique_name('sim2real-alias-')}@example.com"
    for u in (user_a, user_b):
        cognito.admin_create_user(
            UserPoolId=pool_id, Username=u, TemporaryPassword="TempPass!23", MessageAction="SUPPRESS"
        )

    # user A claims the alias email (admin-set, pre-verified)
    cognito.admin_update_user_attributes(
        UserPoolId=pool_id,
        Username=user_a,
        UserAttributes=[
            {"Name": "email", "Value": shared_email},
            {"Name": "email_verified", "Value": "true"},
        ],
    )

    # the alias index is updated asynchronously -- poll until the email alias is
    # actually resolvable to user A before relying on the uniqueness constraint
    _poll_until(
        lambda: cognito.list_users(UserPoolId=pool_id, Filter=f'email = "{shared_email}"'),
        lambda resp: any(u["Username"] == user_a for u in resp.get("Users", [])),
    )

    # success path: update a plain mutable attribute (nickname) on user B
    resp = cognito.admin_update_user_attributes(
        UserPoolId=pool_id,
        Username=user_b,
        UserAttributes=[{"Name": "nickname", "Value": "sim2real-nick"}],
    )
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, resp["ResponseMetadata"]
    got = cognito.admin_get_user(UserPoolId=pool_id, Username=user_b)
    attrs = {a["Name"]: a["Value"] for a in got["UserAttributes"]}
    assert attrs.get("nickname") == "sim2real-nick", attrs

    # distinct behavior boundary: user B claims the same verified email alias as
    # user A -- this SUCCEEDS (no AliasExistsException from the admin path) and
    # the alias is reassigned: the email now resolves to user B, and user A's copy
    # of the attribute is de-verified since only one user may hold the verified
    # alias at a time.
    resp2 = cognito.admin_update_user_attributes(
        UserPoolId=pool_id,
        Username=user_b,
        UserAttributes=[
            {"Name": "email", "Value": shared_email},
            {"Name": "email_verified", "Value": "true"},
        ],
    )
    assert resp2["ResponseMetadata"]["HTTPStatusCode"] == 200, resp2["ResponseMetadata"]

    # the alias index update is asynchronous -- poll until user B's copy of the
    # attribute is verified and user A's copy is de-verified. We check each
    # user's own attributes with AdminGetUser rather than relying on the
    # ListUsers email-attribute Filter: that filter matches literal attribute
    # values, so it keeps matching user A too (their "email" attribute value
    # is unchanged, only "email_verified" flips to false) -- it never becomes
    # exclusive to user B, so it can't be used as an ownership signal.
    def _attrs(username):
        resp = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
        return {a["Name"]: a["Value"] for a in resp["UserAttributes"]}

    attrs_a, attrs_b = _poll_until(
        lambda: (_attrs(user_a), _attrs(user_b)),
        lambda pair: pair[1].get("email") == shared_email
        and pair[1].get("email_verified") == "true"
        and pair[0].get("email_verified") == "false",
    )
    assert attrs_b.get("email") == shared_email and attrs_b.get("email_verified") == "true", attrs_b
    assert attrs_a.get("email_verified") == "false", attrs_a


def _poll_until(fn, predicate, timeout=30, interval=2):
    deadline = time.time() + timeout
    result = None
    while time.time() < deadline:
        result = fn()
        if predicate(result):
            return result
        time.sleep(interval)
    raise AssertionError(f"condition not met within {timeout}s; last={result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
