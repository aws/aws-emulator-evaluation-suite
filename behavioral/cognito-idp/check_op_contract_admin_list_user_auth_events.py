"""op-contract-adminListUserAuthEvents."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-adminListUserAuthEvents"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_PASSWORD = "TestPassw0rd!23"
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With advanced security on, AdminListUserAuthEvents lists a login as a SignIn event with an id and
    CreationDate; on a pool without it the call fails with UserPoolAddOnNotEnabledException and its
    exact message, and once the same pool enables it, returns an empty list for that user."""
    idp = ctx.client("cognito-idp")

    # Pool WITH advanced security enabled (requires the PLUS tier): prove the operation actually
    # surfaces a real event, not just a well-shaped empty list.
    secure_pool_id = _create_user_pool(
        ctx, UserPoolTier="PLUS", UserPoolAddOns={"AdvancedSecurityMode": "AUDIT"}
    )
    secure_client_id = _create_client(ctx, secure_pool_id)
    secure_username = _create_user(ctx, secure_pool_id, _unique(ctx, "user"), _PASSWORD)

    before = idp.admin_list_user_auth_events(UserPoolId=secure_pool_id, Username=secure_username)
    assert before["AuthEvents"] == [], f"expected no events before any sign-in, got {before['AuthEvents']}"

    login = idp.admin_initiate_auth(
        UserPoolId=secure_pool_id,
        ClientId=secure_client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": secure_username, "PASSWORD": _PASSWORD},
    )
    assert "AuthenticationResult" in login, f"expected a completed login, got a challenge: {login}"

    events = _poll_until(
        lambda: idp.admin_list_user_auth_events(
            UserPoolId=secure_pool_id, Username=secure_username
        )["AuthEvents"],
        lambda evs: len(evs) >= 1,
        timeout_s=60,
        interval_s=5,
        description="the sign-in to appear in AdminListUserAuthEvents",
    )
    event = events[0]
    assert event["EventType"] == "SignIn", f"expected a SignIn event, got {event['EventType']}"
    assert event["EventResponse"] in ("Pass", "Fail", "InProgress"), event["EventResponse"]
    assert event["EventId"], "expected a non-empty EventId"
    assert event.get("CreationDate") is not None, "expected a CreationDate on the recorded event"

    # Pool WITHOUT the advanced-security add-on: the same call is rejected outright -- and, on
    # this SAME pool, starts succeeding once the add-on is switched on, isolating the add-on as
    # the cause rather than some other difference between two independently-created pools.
    plain_pool_id = _create_user_pool(ctx)
    plain_username = _create_user(ctx, plain_pool_id, _unique(ctx, "user"), _PASSWORD)

    err = _client_error(
        lambda: idp.admin_list_user_auth_events(UserPoolId=plain_pool_id, Username=plain_username)
    )
    assert err.get("Code") == "UserPoolAddOnNotEnabledException", (
        f"expected UserPoolAddOnNotEnabledException, got {err.get('Code')}"
    )
    assert err.get("Message") == "This is an add on feature. Please update AdvancedSecurityMode for your user pool to access this API.", err.get("Message")

    idp.update_user_pool(
        UserPoolId=plain_pool_id,
        UserPoolTier="PLUS",
        UserPoolAddOns={"AdvancedSecurityMode": "AUDIT"},
    )
    restored = _poll_until(
        lambda: _try_list_events(idp, plain_pool_id, plain_username),
        lambda r: r is not None,
        timeout_s=30,
        interval_s=3,
        description="the identical AdminListUserAuthEvents call to accept once the add-on is enabled",
    )
    assert restored == [], f"expected no events for a user who never signed in, got {restored}"


def _unique(ctx, kind: str) -> str:
    return ctx.unique_name(f"sim2real-behav-{kind}-")


def _create_user_pool(ctx, **kwargs):
    idp = ctx.client("cognito-idp")
    kwargs.setdefault("UserPoolTags", _POOL_TAGS)
    pool_id = idp.create_user_pool(PoolName=_unique(ctx, "pool"), **kwargs)["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_client(ctx, pool_id) -> str:
    idp = ctx.client("cognito-idp")
    client = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=_unique(ctx, "client"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]
    client_id = client["ClientId"]
    ctx.on_cleanup(lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    return client_id


def _create_user(ctx, pool_id, username, password=None, permanent=True, attrs=None):
    idp = ctx.client("cognito-idp")
    kwargs = {
        "UserPoolId": pool_id,
        "Username": username,
        "MessageAction": "SUPPRESS",
        "UserAttributes": attrs
        or [
            {"Name": "email", "Value": f"{username}@example.com"},
            {"Name": "email_verified", "Value": "true"},
        ],
    }
    if password:
        kwargs["TemporaryPassword"] = password
    idp.admin_create_user(**kwargs)
    ctx.on_cleanup(lambda: _safe_delete_user(ctx, pool_id, username))
    if password and permanent:
        idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    return username


def _safe_delete_user(ctx, pool_id, username) -> None:
    idp = ctx.client("cognito-idp")
    try:
        idp.admin_delete_user(UserPoolId=pool_id, Username=username)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "UserNotFoundException",
        ):
            raise


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _try_list_events(idp, pool_id, username):
    """None while the add-on is still off (the expected, waited-for state); raise on anything
    else, so a genuinely broken target cannot hide behind the poll."""
    try:
        return idp.admin_list_user_auth_events(UserPoolId=pool_id, Username=username)["AuthEvents"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "UserPoolAddOnNotEnabledException":
            return None
        raise


def _poll_until(fn, predicate, *, timeout_s, interval_s, description):
    import time

    deadline = time.monotonic() + timeout_s
    last = fn()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out waiting for {description}; last={last!r}")
        time.sleep(interval_s)
        last = fn()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
