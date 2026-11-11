"""op-contract-update-auth-event-feedback."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-update-auth-event-feedback"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateAuthEventFeedback is refused with UserPoolAddOnNotEnabledException without advanced
    security, and with NotAuthorizedException for a bogus FeedbackToken on a pool that has it."""
    cognito = ctx.client("cognito-idp")
    pool_tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

    # A genuine FeedbackToken is only delivered by email for a real risk event, so only the
    # error boundaries are exercised.
    plain_pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-authfb-plain-"),
        UserPoolTags=pool_tags,
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_pool(cognito, plain_pool_id))

    username = ctx.unique_name("sim2real-user-")
    cognito.admin_create_user(
        UserPoolId=plain_pool_id, Username=username, MessageAction="SUPPRESS"
    )
    ctx.on_cleanup(
        lambda: cognito.admin_delete_user(UserPoolId=plain_pool_id, Username=username)
    )

    code, message = _error(
        lambda: cognito.update_auth_event_feedback(
            UserPoolId=plain_pool_id,
            Username=username,
            EventId="00000000-0000-0000-0000-000000000000",
            FeedbackToken="bogus-token",
            FeedbackValue="Valid",
        )
    )
    assert code == "UserPoolAddOnNotEnabledException", code
    addon_message = (
        "This is an add on feature. Please update AdvancedSecurityMode for your user pool to access this API."
    )
    assert message == addon_message, f"expected message {addon_message!r}, got {message!r}"

    # The same feature gate also refuses the event-history read.
    read_code, read_message = _error(
        lambda: cognito.admin_list_user_auth_events(UserPoolId=plain_pool_id, Username=username)
    )
    assert read_code == "UserPoolAddOnNotEnabledException", read_code
    assert read_message == addon_message, f"expected message {addon_message!r}, got {read_message!r}"

    # The token is validated before the user/event is looked up, so a bogus token yields
    # NotAuthorizedException even though the user does not exist.
    plus_pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-authfb-plus-"),
        UserPoolTier="PLUS",
        UserPoolAddOns={"AdvancedSecurityMode": "AUDIT"},
        UserPoolTags=pool_tags,
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_pool(cognito, plus_pool_id))

    code2, message2 = _error(
        lambda: cognito.update_auth_event_feedback(
            UserPoolId=plus_pool_id,
            Username="no-such-user-ever",
            EventId="00000000-0000-0000-0000-000000000000",
            FeedbackToken="bogus-token",
            FeedbackValue="Valid",
        )
    )
    assert code2 == "NotAuthorizedException", code2
    expected = "Invalid session provided"
    assert message2 == expected, f"expected message {expected!r}, got {message2!r}"

    # Confirms the user is absent, so the refusal above came from token validation.
    try:
        cognito.admin_get_user(UserPoolId=plus_pool_id, Username="no-such-user-ever")
    except ClientError as exc:
        lookup_code = exc.response["Error"]["Code"]
        assert lookup_code == "UserNotFoundException", lookup_code
        lookup_message = exc.response["Error"].get("Message")
        assert lookup_message == "User does not exist.", (
            f"expected message 'User does not exist.', got {lookup_message!r}"
        )
    else:
        raise AssertionError(
            "admin_get_user unexpectedly found a user this check never created"
        )


def _delete_pool(cognito, pool_id):
    try:
        cognito.delete_user_pool(UserPoolId=pool_id)
    except ClientError as exc:
        teardown_code = exc.response.get("Error", {}).get("Code", "")
        if teardown_code not in ("ResourceNotFoundException",):
            raise RuntimeError(
                f"user pool {pool_id!r} not deleted: {exc.response.get('Error', {}).get('Code')}"
            ) from exc


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
