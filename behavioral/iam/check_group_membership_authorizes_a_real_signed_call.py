"""group-membership-authorizes-a-real-signed-call."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "group-membership-authorizes-a-real-signed-call"
GROUP = 'groups'
SERVICES = ['iam']

_PROPAGATION = frozenset({"InvalidClientTokenId", "SignatureDoesNotMatch"})
_GROUP_POLICY = "sim2real-behav-grp-getuser"


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _outcome(fn):
    """(code, message) of the captured AWS error, or a sentinel pair that cannot be mistaken for
    one on success."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    return "UNEXPECTED_SUCCESS", None


def _client_for_credentials(ctx, access_key_id, secret_access_key, service="iam"):
    """A client signing AS the minted principal, through the engine's re-signing idiom: it keeps
    THIS target's endpoint, region and TLS settings."""
    return ctx.client(
        service,
        creds={"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_access_key},
    )


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


def _members(iam, group):
    """Every member of the group, paginated -- a shared pool can push a user off page one."""
    names = []
    paginator = iam.get_paginator("get_group")
    for page in paginator.paginate(GroupName=group):
        names.extend(u["UserName"] for u in page.get("Users", []))
    return names


def _leave_group(iam, group, user):
    """Teardown-only: the body removes the membership itself, so tolerate it already being gone."""
    try:
        iam.remove_user_from_group(GroupName=group, UserName=user)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


# The AccessDenied message ends in a per-call authorization id (also embedded in the console
# URL), so the full string is never repeatable: the message varies per call in that one token,
# and a full match pins every other character.
_AUTHZ_TAIL = (
    r"\. Go to https://\S+ for complete details, or call the GetRequestAuthorizationDetails "
    r"API with the following authorization id: [A-Za-z0-9]+"
)


def _expected_denial(message, head):
    """``head`` followed by the authorization-details pointer that ends ``message``: the pointer's
    region and per-request authorization id are the only parts read back from it."""
    found = re.search(_AUTHZ_TAIL + r"\Z", message or "")
    return head + (found.group(0) if found else ". Go to <authorization-details pointer>")


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """A grant held only by a group authorizes a member's real signed call: the user is refused with
    AccessDenied and the exact no-policy message before joining, allowed while a member, and refused
    the same way again after removal."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-grp-user-")
    group = ctx.unique_name("sim2real-behav-grp-")

    iam.create_user(UserName=user, Path="/")
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    user_arn = iam.get_user(UserName=user)["User"]["Arn"]

    iam.create_group(GroupName=group, Path="/")
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group))
    iam.put_group_policy(
        GroupName=group,
        PolicyName=_GROUP_POLICY,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "iam:GetUser", "Resource": user_arn}],
        }),
    )
    ctx.on_cleanup(
        lambda: iam.delete_group_policy(GroupName=group, PolicyName=_GROUP_POLICY)
    )

    key = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"])
    )
    as_user = _client_for_credentials(ctx, key["AccessKeyId"], key["SecretAccessKey"])

    # --- Pre-state: NOT a member yet, and holding no identity policy, so nothing can authorize
    #     this call. Poll past credential replication only -- AccessDenied here is the answer.
    before = _poll(
        lambda: _outcome(lambda: as_user.get_user(UserName=user)),
        lambda o: o[0] not in _PROPAGATION,
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the freshly minted access key stops being rejected as unreplicated",
    )
    no_allow = (
        f"User: {user_arn} is not authorized to perform: iam:GetUser on resource: user {user} "
        "because no identity-based policy allows the iam:GetUser action"
    )
    before_code, before_message = before
    assert before_code == "AccessDenied" and before_message == _expected_denial(before_message, no_allow), (
        "a user with no identity policy and no group must be refused with exactly AccessDenied "
        f"for lack of an allow before joining; got {before!r} -- anything else means something "
        "else authorized it"
    )

    # --- Break exactly one thing, in the permitting direction: join the group.
    iam.add_user_to_group(GroupName=group, UserName=user)
    ctx.on_cleanup(lambda: _leave_group(iam, group, user))
    joined = _members(iam, group)
    assert user in joined, (
        f"membership must be observable before anything is inferred from it: {user!r} not in "
        f"{joined!r}"
    )

    during = _poll(
        lambda: _outcome(lambda: as_user.get_user(UserName=user)),
        lambda o: o[0] == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the group's inherited permission takes effect on the real signed GetUser",
    )
    assert during[0] == "UNEXPECTED_SUCCESS", (
        "the group policy is the ONLY grant in play, so the real signed GetUser must succeed while "
        f"the user is a member; got {during!r} -- group inheritance is not enforced"
    )

    # --- Reverse it: removal must revoke, so the success was caused by membership alone.
    iam.remove_user_from_group(GroupName=group, UserName=user)
    after = _poll(
        lambda: _outcome(lambda: as_user.get_user(UserName=user)),
        lambda o: o[0] == "AccessDenied",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="leaving the group revokes the inherited permission",
    )
    after_code, after_message = after
    assert after_code == "AccessDenied" and after_message == _expected_denial(after_message, no_allow), (
        "removing the only grant must refuse the real signed call with exactly AccessDenied, for "
        "lack of an allow, again; "
        f"got {after!r} -- the permission outlived the membership"
    )
    left = _members(iam, group)
    assert user not in left, (
        f"the two views must agree at both ends: {user!r} is still in the paginated membership "
        f"{left!r} after remove_user_from_group"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
