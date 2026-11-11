"""auth-event-history-chronological-order."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "auth-event-history-chronological-order"
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


def _err(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises AssertionError, so an emulator accepting what AWS refuses never reads as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _is_monotonic(seq):
    """True if seq is non-decreasing OR non-increasing (order-direction-agnostic: Cognito doesn't
    document which direction AdminListUserAuthEvents sorts, so verify consistency, not direction)."""
    if len(seq) < 2:
        return True
    asc = all(seq[i] <= seq[i + 1] for i in range(len(seq) - 1))
    desc = all(seq[i] >= seq[i + 1] for i in range(len(seq) - 1))
    return asc or desc


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


def _user_login(c, client_id, username, password):
    resp = c.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return resp["AuthenticationResult"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """AdminListUserAuthEvents keeps a monotonic CreationDate order as events are added, feedback
    lands only on the targeted event, and a fabricated FeedbackToken is refused with
    NotAuthorizedException "Invalid session provided" without changing any event."""
    c = ctx.client("cognito-idp")
    pool_id = _new_pool(
        ctx,
        c,
        AutoVerifiedAttributes=["email"],
        UserPoolTier="PLUS",
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
    events1 = _poll_until(
        lambda: c.admin_list_user_auth_events(UserPoolId=pool_id, Username=username)["AuthEvents"],
        lambda evs: len(evs) >= 1,
        timeout_s=60,
        interval_s=5,
        description="first recorded auth event",
    )
    old_event_id = events1[0]["EventId"]
    old_creation = events1[0]["CreationDate"]

    _user_login(c, client_id, username, password)
    events2 = _poll_until(
        lambda: c.admin_list_user_auth_events(UserPoolId=pool_id, Username=username)["AuthEvents"],
        lambda evs: len(evs) >= 2 and any(e["EventId"] != old_event_id for e in evs),
        timeout_s=60,
        interval_s=5,
        description="second recorded auth event",
    )

    ids2 = [e["EventId"] for e in events2]
    assert old_event_id in ids2, f"the earlier event {old_event_id} disappeared from history: {ids2}"

    creation_dates = [e["CreationDate"] for e in events2]
    assert _is_monotonic(creation_dates), (
        f"AdminListUserAuthEvents is not in a consistent chronological order: {creation_dates}"
    )

    new_candidates = [e for e in events2 if e["EventId"] != old_event_id]
    assert new_candidates, "expected a second, distinct auth event after the second login"
    new_event = max(new_candidates, key=lambda e: e["CreationDate"])
    new_event_id = new_event["EventId"]
    assert new_event["CreationDate"] >= old_creation, (
        "the later login's event must not be timestamped before the earlier login's event"
    )

    c.admin_update_auth_event_feedback(
        UserPoolId=pool_id, Username=username, EventId=old_event_id, FeedbackValue="Valid"
    )
    events3 = c.admin_list_user_auth_events(UserPoolId=pool_id, Username=username)["AuthEvents"]
    by_id3 = {e["EventId"]: e for e in events3}
    assert by_id3[old_event_id].get("EventFeedback", {}).get("FeedbackValue") == "Valid", (
        f"feedback did not attach to the targeted historical event {old_event_id}: "
        f"{by_id3[old_event_id]}"
    )
    assert not by_id3.get(new_event_id, {}).get("EventFeedback"), (
        f"feedback bled onto the wrong (newer) event {new_event_id}: {by_id3.get(new_event_id)}"
    )

    # The self-service UpdateAuthEventFeedback is authorized by a Cognito-issued FeedbackToken
    # delivered in a real risk-notification email (unobtainable here); a fabricated token MUST be
    # rejected rather than silently accepted and attached to an event.
    bogus_feedback_token = "eyJub25lIjoidHJ1ZSJ9.sim2real-bogus-feedback-token_01234567"
    code_bogus, code_bogus_msg = _err(
        lambda: c.update_auth_event_feedback(
            UserPoolId=pool_id,
            Username=username,
            EventId=new_event_id,
            FeedbackToken=bogus_feedback_token,
            FeedbackValue="Invalid",
        )
    )
    assert code_bogus == "NotAuthorizedException", (
        f"expected UpdateAuthEventFeedback to reject a fabricated FeedbackToken as "
        f"NotAuthorizedException, got {code_bogus!r}"
    )
    assert code_bogus_msg == 'Invalid session provided', f"expected the exact {code_bogus} message, got {code_bogus_msg!r}"

    events4 = c.admin_list_user_auth_events(UserPoolId=pool_id, Username=username)["AuthEvents"]
    by_id4 = {e["EventId"]: e for e in events4}
    assert not by_id4.get(new_event_id, {}).get("EventFeedback"), (
        "a rejected UpdateAuthEventFeedback call must not have attached any feedback"
    )
    assert by_id4[old_event_id].get("EventFeedback", {}).get("FeedbackValue") == "Valid", (
        "the earlier successful feedback attachment must remain unaffected by the failed call"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
