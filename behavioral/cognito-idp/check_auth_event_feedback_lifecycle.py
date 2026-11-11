"""auth-event-feedback-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "auth-event-feedback-lifecycle"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]

_PASSWORD = "S1mParity!Behave2024"


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """AdminListUserAuthEvents surfaces sign-in events; feedback APIs persist a feedback value on them."""
    cognito = ctx.client("cognito-idp")

    try:
        pool_id = cognito.create_user_pool(
            PoolName=ctx.unique_name("sim2real-behav-pool-"),
            UserPoolAddOns={"AdvancedSecurityMode": "AUDIT"},
            UserPoolTags={"sim2real:managed": "true", "sim2real:check": CHECK},
        )["UserPool"]["Id"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "FeatureUnavailableInTierException":
            raise AssertionError("threat protection / advanced security not available for this account tier")
        raise
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))

    username = ctx.unique_name("sim2real-behav-user-")
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}, {"Name": "email_verified", "Value": "true"}],
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(
        lambda: _ignore_errors(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    )
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=_PASSWORD, Permanent=True)

    cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
    )

    try:
        events = _poll_until(
            lambda: cognito.admin_list_user_auth_events(UserPoolId=pool_id, Username=username).get(
                "AuthEvents", []
            ),
            lambda evs: len(evs) > 0,
            timeout_s=90.0,
            interval_s=5.0,
        )
    except AssertionError:
        raise AssertionError("no auth event was recorded within the polling window")
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "UserPoolAddOnNotEnabledException":
            raise AssertionError("threat protection not enabled on the pool")
        raise

    event_id = events[0]["EventId"]

    cognito.admin_update_auth_event_feedback(
        UserPoolId=pool_id, Username=username, EventId=event_id, FeedbackValue="Valid"
    )
    updated_events = cognito.admin_list_user_auth_events(UserPoolId=pool_id, Username=username)["AuthEvents"]
    by_id = {e["EventId"]: e for e in updated_events}
    assert by_id[event_id]["EventFeedback"]["FeedbackValue"] == "Valid", by_id[event_id]

    cognito.admin_update_auth_event_feedback(
        UserPoolId=pool_id, Username=username, EventId=event_id, FeedbackValue="Invalid"
    )
    updated_events2 = cognito.admin_list_user_auth_events(UserPoolId=pool_id, Username=username)["AuthEvents"]
    by_id2 = {e["EventId"]: e for e in updated_events2}
    assert by_id2[event_id]["EventFeedback"]["FeedbackValue"] == "Invalid", by_id2[event_id]

    # negative boundary: the self-service path requires a genuine FeedbackToken (delivered out-of-band);
    # a fabricated token must be rejected, not silently accepted.
    code, code_msg = _error_code(
        lambda: cognito.update_auth_event_feedback(
            UserPoolId=pool_id,
            Username=username,
            EventId=event_id,
            FeedbackToken="sim2real-bogus-feedback-token",
            FeedbackValue="Valid",
        )
    )
    assert code == "NotAuthorizedException", code
    assert code_msg == 'Invalid session provided', f"expected the exact {code} message, got {code_msg!r}"

    # the rejected self-service call must not have overwritten the feedback the admin call set.
    post_reject_events = cognito.admin_list_user_auth_events(UserPoolId=pool_id, Username=username)[
        "AuthEvents"
    ]
    by_id3 = {e["EventId"]: e for e in post_reject_events}
    assert by_id3[event_id]["EventFeedback"]["FeedbackValue"] == "Invalid", by_id3[event_id]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _ignore_errors(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "UserNotFoundException",
        ):
            raise


def _error_code(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises AssertionError, so an emulator accepting what AWS refuses never reads as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
