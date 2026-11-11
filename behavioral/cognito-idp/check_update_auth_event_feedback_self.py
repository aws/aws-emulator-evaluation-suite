"""update-auth-event-feedback-self."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-auth-event-feedback-self"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """AdminUpdateAuthEventFeedback sets Valid feedback on a real auth event, while UpdateAuthEventFeedback
    with an unminted FeedbackToken fails with NotAuthorizedException and its exact message and leaves
    the feedback Valid."""
    cog = ctx.client("cognito-idp")
    password = "Sim2RealP@ss9142"

    try:
        pool_id = cog.create_user_pool(
            PoolName=ctx.unique_name("sim2real-behav-selffb-pool-"),
            UserPoolTier="PLUS",
            UserPoolAddOns={"AdvancedSecurityMode": "AUDIT"},
            UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        )["UserPool"]["Id"]
    except cog.exceptions.FeatureUnavailableInTierException:
        raise AssertionError("Plus tier / advanced security add-on unavailable for this account")
    ctx.on_cleanup(lambda: cog.delete_user_pool(UserPoolId=pool_id))

    client_id = cog.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-selffb-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("selffbuser-")
    cog.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    cog.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    cog.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )

    event_id = _poll_for_event(cog, pool_id, username, timeout_s=120.0)
    if event_id is None:
        raise AssertionError("no auth event materialized under advanced security audit mode in time")

    # Positive control: an IAM-authorized admin caller CAN set feedback on this real event.
    cog.admin_update_auth_event_feedback(
        UserPoolId=pool_id, Username=username, EventId=event_id, FeedbackValue="Valid",
    )
    established = _poll_feedback(cog, pool_id, username, event_id, "Valid", timeout_s=60.0)
    assert established == "Valid", f"admin positive control failed to establish feedback, saw {established!r}"

    # Negative: the self-service path needs a genuine FeedbackToken minted into a notification
    # email. A syntactically-valid but bogus token acts as an invalid credential for the
    # unauthenticated feedback API, so Cognito rejects it as NotAuthorizedException rather
    # than as a malformed-parameter error -- it must be rejected, not silently accepted.
    bogus_token = "A" * 64
    code, message = _error(
        lambda: cog.update_auth_event_feedback(
            UserPoolId=pool_id,
            Username=username,
            EventId=event_id,
            FeedbackToken=bogus_token,
            FeedbackValue="Invalid",
        )
    )
    assert code == "NotAuthorizedException", f"expected NotAuthorizedException, got {code!r}"
    assert message == "Invalid session provided", (
        f"expected the exact unminted-FeedbackToken message, got {message!r}"
    )

    # The forbidden effect must be absent: feedback is still what the admin call set, not
    # overwritten by the rejected self-service attempt.
    unchanged = _poll_feedback(cog, pool_id, username, event_id, "Valid", timeout_s=30.0)
    assert unchanged == "Valid", f"rejected self-feedback call mutated state to {unchanged!r}"


def _error(fn):
    """Run fn and return the (code, message) AWS refused it with. An unexpected success raises."""
    try:
        result = fn()
    except Exception as exc:  # botocore.exceptions.ClientError
        error = getattr(exc, "response", {}).get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        f"expected the self-service call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _poll_for_event(cog, pool_id: str, username: str, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cog.admin_list_user_auth_events(UserPoolId=pool_id, Username=username, MaxResults=20)
        events = resp.get("AuthEvents", [])
        if events:
            return events[0]["EventId"]
        time.sleep(2)
    return None


def _poll_feedback(cog, pool_id: str, username: str, event_id: str, expected: str, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cog.admin_list_user_auth_events(UserPoolId=pool_id, Username=username, MaxResults=20)
        for ev in resp.get("AuthEvents", []):
            if ev["EventId"] == event_id:
                last = ev.get("EventFeedback", {}).get("FeedbackValue")
                if last == expected:
                    return last
        time.sleep(5.0)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
