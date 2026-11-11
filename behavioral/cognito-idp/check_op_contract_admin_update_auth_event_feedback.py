"""op-contract-adminUpdateAuthEventFeedback."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-adminUpdateAuthEventFeedback"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_PASSWORD = "TestPassw0rd!23"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AdminUpdateAuthEventFeedback records Valid feedback on a real auth event with advanced security on,
    and fails with UserPoolAddOnNotEnabledException when it is off and ResourceNotFoundException for a
    missing pool, each with its exact message."""
    cognito = ctx.client("cognito-idp")

    # Positive control: with advanced security enabled and a real sign-in producing a
    # real auth event, the call succeeds and the feedback value persists -- verified by
    # an independent read (AdminListUserAuthEvents) at the destination.
    secure_pool_id = _create_user_pool(
        ctx, UserPoolTier="PLUS", UserPoolAddOns={"AdvancedSecurityMode": "AUDIT"}
    )
    client_id = cognito.create_user_pool_client(
        UserPoolId=secure_pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda: cognito.delete_user_pool_client(UserPoolId=secure_pool_id, ClientId=client_id)
    )

    secure_username = ctx.unique_name("sim2real-user-")
    cognito.admin_create_user(
        UserPoolId=secure_pool_id, Username=secure_username, MessageAction="SUPPRESS"
    )
    ctx.on_cleanup(
        lambda: _ignore_errors(
            lambda: cognito.admin_delete_user(UserPoolId=secure_pool_id, Username=secure_username)
        )
    )
    cognito.admin_set_user_password(
        UserPoolId=secure_pool_id, Username=secure_username, Password=_PASSWORD, Permanent=True
    )
    cognito.admin_initiate_auth(
        UserPoolId=secure_pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": secure_username, "PASSWORD": _PASSWORD},
    )

    events = _poll_until(
        lambda: cognito.admin_list_user_auth_events(
            UserPoolId=secure_pool_id, Username=secure_username
        ).get("AuthEvents", []),
        lambda evs: len(evs) > 0,
        timeout_s=90.0,
        interval_s=5.0,
    )
    event_id = events[0]["EventId"]

    cognito.admin_update_auth_event_feedback(
        UserPoolId=secure_pool_id,
        Username=secure_username,
        EventId=event_id,
        FeedbackValue="Valid",
    )
    reread = cognito.admin_list_user_auth_events(
        UserPoolId=secure_pool_id, Username=secure_username
    )["AuthEvents"]
    by_id = {e["EventId"]: e for e in reread}
    assert by_id[event_id]["EventFeedback"]["FeedbackValue"] == "Valid", by_id[event_id]

    # Boundary 1: a fresh user pool has no threat-protection (advanced security)
    # add-on enabled, so feedback on any event -- real or not -- is rejected at the
    # feature-gate check. EventId must be a well-formed GUID (Cognito's real event-id
    # format) -- an arbitrary string like "sim2real-fake-event-id" fails GUID-shape
    # parameter validation FIRST (InvalidParameterException) and never reaches the
    # add-on feature-gate check. FeedbackValue is an enum whose real values are the
    # title-cased "Valid"/"Invalid" (not "VALID"/"INVALID") -- passing the
    # upper-cased spelling fails enum-shape parameter validation FIRST
    # (InvalidParameterException), before the request ever reaches the add-on
    # feature-gate check.
    plain_pool_id = _create_user_pool(ctx)
    plain_username = ctx.unique_name("sim2real-user-")
    cognito.admin_create_user(
        UserPoolId=plain_pool_id,
        Username=plain_username,
        TemporaryPassword="TempPass!23",
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(
        lambda: _ignore_errors(
            lambda: cognito.admin_delete_user(UserPoolId=plain_pool_id, Username=plain_username)
        )
    )
    cognito.admin_set_user_password(
        UserPoolId=plain_pool_id, Username=plain_username, Password="TempPass!23", Permanent=True
    )

    code = _client_error(
        lambda: cognito.admin_update_auth_event_feedback(
            UserPoolId=plain_pool_id,
            Username=plain_username,
            EventId=str(uuid.uuid4()),
            FeedbackValue="Valid",
        )
    )
    assert code.get("Code") == "UserPoolAddOnNotEnabledException", code
    assert code.get("Message") == "This is an add on feature. Please update AdvancedSecurityMode for your user pool to access this API.", code.get("Message")

    # distinct error boundary: pool does not exist at all
    missing_pool_id = f"{ctx.region}_doesnotexist99"
    code2 = _client_error(
        lambda: cognito.admin_update_auth_event_feedback(
            UserPoolId=missing_pool_id,
            Username=plain_username,
            EventId=str(uuid.uuid4()),
            FeedbackValue="Valid",
        )
    )
    assert code2.get("Code") == "ResourceNotFoundException", code2
    assert code2.get("Message") == f"User pool {missing_pool_id} does not exist.", code2.get("Message")


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_user_pool(ctx, **kwargs):
    cognito = ctx.client("cognito-idp")
    pool = cognito.create_user_pool(PoolName=ctx.unique_name("sim2real-pool-"), **kwargs)["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _ignore_errors(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "UserNotFoundException",
        ):
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
