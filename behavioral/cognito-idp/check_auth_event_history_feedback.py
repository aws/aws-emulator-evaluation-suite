"""auth-event-history-feedback."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "auth-event-history-feedback"
GROUP = 'auth-state-machine'
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


def _poll_until(fn, predicate, timeout_s, interval_s, description):
    import time

    deadline = time.monotonic() + timeout_s
    last = fn()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out waiting for {description}; last={last!r}")
        time.sleep(interval_s)
        last = fn()
    return last


def _new_pool(ctx, c, **kwargs):
    kwargs.setdefault("Policies", _LENIENT_PASSWORD_POLICY)
    kwargs.setdefault("UserPoolTags", _POOL_TAGS)
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), **kwargs
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _new_client(ctx, c, pool_id, **kwargs):
    kwargs.setdefault("GenerateSecret", False)
    client = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), **kwargs
    )["UserPoolClient"]
    ctx.on_cleanup(
        lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client["ClientId"])
    )
    return client


def _new_confirmed_user(ctx, c, pool_id, password=PASSWORD, **extra_attrs):
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
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    return username, password


def _admin_login(c, pool_id, client_id, username, password):
    resp = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert "AuthenticationResult" in resp, f"expected AuthenticationResult, got a challenge: {resp}"
    return resp["AuthenticationResult"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After a real sign-in, AdminListUserAuthEvents shows at least one auth event for the user, and
    AdminUpdateAuthEventFeedback on that event's EventId succeeds (accepted without error) rather
    than silently failing on an id it never actually recorded."""
    c = ctx.client("cognito-idp")
    pool_id = _new_pool(
        ctx,
        c,
        AutoVerifiedAttributes=["email"],
        UserPoolAddOns={"AdvancedSecurityMode": "AUDIT"},
    )
    client_id = _new_client(
        ctx,
        c,
        pool_id,
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
        ],
    )["ClientId"]
    username, password = _new_confirmed_user(ctx, c, pool_id)
    _admin_login(c, pool_id, client_id, username, password)

    events = _poll_until(
        lambda: c.admin_list_user_auth_events(UserPoolId=pool_id, Username=username)["AuthEvents"],
        lambda evs: len(evs) > 0,
        timeout_s=60,
        interval_s=5,
        description="at least one recorded auth event",
    )
    event_id = events[0]["EventId"]

    c.admin_update_auth_event_feedback(
        UserPoolId=pool_id, Username=username, EventId=event_id, FeedbackValue="Valid"
    )
    updated_events = c.admin_list_user_auth_events(UserPoolId=pool_id, Username=username)["AuthEvents"]
    by_id = {e["EventId"]: e for e in updated_events}
    assert event_id in by_id, f"event {event_id} missing from history after feedback update: {list(by_id)}"
    feedback = by_id[event_id].get("EventFeedback")
    assert feedback is not None, (
        f"AdminUpdateAuthEventFeedback returned success but did not persist feedback on {event_id}: "
        f"{by_id[event_id]!r}"
    )
    assert feedback["FeedbackValue"] == "Valid", feedback


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
