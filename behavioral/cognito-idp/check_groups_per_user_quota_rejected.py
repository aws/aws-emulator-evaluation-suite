"""groups-per-user-quota-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "groups-per-user-quota-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]

_GROUPS_PER_USER = 100
_OVER_QUOTA = ("LimitExceededException", "The limit for addUserToGroup is: 100.")
_THROTTLE_MAX_ATTEMPTS = 8
_THROTTLE_INITIAL_BACKOFF_S = 1.0


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AdminAddUserToGroup succeeds through a user's 100th group membership, the account's
    non-adjustable per-user group quota, and refuses the 101st, leaving membership at 100."""
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda _p=pool_id: cognito.delete_user_pool(UserPoolId=_p))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    cognito.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda _p=pool_id, _u=username: cognito.admin_delete_user(UserPoolId=_p, Username=_u))

    # Positive control: every one of the 100 memberships the quota allows must actually land,
    # including the last one, right up against the boundary the final call then crosses.
    group_prefix = ctx.unique_name("sim2real-behav-cip-group-")
    for i in range(_GROUPS_PER_USER):
        group_name = f"{group_prefix}{i}"
        _retry_throttle(lambda _g=group_name: cognito.create_group(UserPoolId=pool_id, GroupName=_g))
        ctx.on_cleanup(lambda _p=pool_id, _g=group_name: cognito.delete_group(UserPoolId=_p, GroupName=_g))
        _retry_throttle(
            lambda _g=group_name: cognito.admin_add_user_to_group(
                UserPoolId=pool_id, Username=username, GroupName=_g
            )
        )

    at_quota = _list_all_groups_for_user(cognito, pool_id, username)
    assert len(at_quota) == _GROUPS_PER_USER, (
        f"expected {_GROUPS_PER_USER} memberships after reaching the quota, got {len(at_quota)}: {at_quota!r}"
    )

    over_group = f"{group_prefix}over"
    _retry_throttle(lambda: cognito.create_group(UserPoolId=pool_id, GroupName=over_group))
    ctx.on_cleanup(lambda _p=pool_id, _g=over_group: cognito.delete_group(UserPoolId=_p, GroupName=_g))

    expect_error(
        lambda: _retry_throttle(
            lambda: cognito.admin_add_user_to_group(
                UserPoolId=pool_id, Username=username, GroupName=over_group
            )
        ),
        *_OVER_QUOTA,
    )

    # Effect absent: the refused membership did not land, and the quota-holding ones survived.
    unchanged = _list_all_groups_for_user(cognito, pool_id, username)
    assert over_group not in unchanged, (
        f"the refused group {over_group!r} appears in membership after the rejected call: {unchanged!r}"
    )
    assert len(unchanged) == _GROUPS_PER_USER, (
        f"membership count drifted from the quota after the rejected call: {len(unchanged)}"
    )


# ===== helpers =====


def _list_all_groups_for_user(cognito, pool_id: str, username: str) -> list[str]:
    """Every GroupName AdminListGroupsForUser reports for ``username``, paginated."""
    names: list[str] = []
    token = None
    while True:
        kwargs = {"UserPoolId": pool_id, "Username": username}
        if token:
            kwargs["NextToken"] = token
        page = _retry_throttle(lambda _kw=kwargs: cognito.admin_list_groups_for_user(**_kw))
        names.extend(g["GroupName"] for g in page["Groups"])
        token = page.get("NextToken")
        if not token:
            return names


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _retry_throttle(fn):
    """Retry ``fn`` on the documented TooManyRequestsException with backoff, bounded so a
    persistently throttled account fails loudly instead of stalling. Any other ClientError
    (including LimitExceededException, the code this check exists to assert) propagates as is."""
    delay = _THROTTLE_INITIAL_BACKOFF_S
    for attempt in range(_THROTTLE_MAX_ATTEMPTS):
        try:
            return fn()
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "TooManyRequestsException"
                or attempt == _THROTTLE_MAX_ATTEMPTS - 1
            ):
                raise
            time.sleep(delay)
            delay = min(delay * 1.5, 5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
