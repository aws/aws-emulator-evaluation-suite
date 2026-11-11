"""group-policy-explicit-deny-overrides-the-users-own-allow."""
from __future__ import annotations

import json
import re
import time
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "group-policy-explicit-deny-overrides-the-users-own-allow"
GROUP = "groups"
SERVICES = ["iam"]

_USER_ALLOW = "sim2real-behav-groupdeny-user-allow"
_GROUP_DENY = "sim2real-behav-groupdeny-group-deny"
_SUBJECT = "iam:GetUser"
_SIBLING = "iam:ListUserTags"
_MARK = [{"Key": "sim2real", "Value": CHECK}]


def _denial_message(fn):
    """Error.Message of a call real AWS refuses; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Message") or ""
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


# An AccessDenied ends with a pointer to a server-minted, per-request authorization id, given
# twice (in a console URL and on its own); every other character is pinned.
_AUTHZ_TAIL = (
    r"\. Go to https://[a-z0-9-]+\.console\.aws\.amazon\.com/iam/home\?region=[a-z0-9-]+"
    r"#/authorization-details/(\w+) for complete details, or call the GetRequestAuthorizationDetails "
    r"API with the following authorization id: \1"
)


def _expected_denial(message, head):
    """``head`` followed by the authorization-details pointer that ends ``message``: the pointer's
    region and per-request authorization id are the only parts read back from it."""
    found = re.search(_AUTHZ_TAIL + r"\Z", message or "")
    return head + (found.group(0) if found else ". Go to <authorization-details pointer>")


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A group policy's explicit Deny overrides the member's own inline Allow: the signed call gets
    AccessDenied and the exact message while a sibling action works, the simulator says explicitDeny,
    and leaving the group restores access while the group's Deny still exists."""
    iam = ctx.client("iam")

    user = ctx.unique_name("sim2real-gdeny-user-")
    iam.create_user(UserName=user, Path="/", Tags=_MARK)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    user_arn = iam.get_user(UserName=user)["User"]["Arn"]

    group = ctx.unique_name("sim2real-gdeny-group-")
    iam.create_group(GroupName=group, Path="/")
    # DeleteGroup needs the group's inline policies and members gone first; cleanups run in reverse.
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group))
    ctx.on_cleanup(lambda: _leave_group(iam, group, user))
    ctx.on_cleanup(lambda: _drop_group_policy(iam, group, _GROUP_DENY))

    iam.put_user_policy(
        UserName=user,
        PolicyName=_USER_ALLOW,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [_SUBJECT, _SIBLING],
                "Resource": user_arn,
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user, PolicyName=_USER_ALLOW))

    iam.add_user_to_group(GroupName=group, UserName=user)
    members = [m["UserName"] for m in iam.get_group(GroupName=group)["Users"]]
    assert members == [user], (
        f"the group must contain exactly the one user this check created before any conclusion is "
        f"drawn from the group edge; expected [{user!r}], GetGroup reports {members!r}"
    )

    key = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"]))
    as_user = _signing_as(ctx, "iam", key)

    # Without this positive control, AccessDenied below is indistinguishable from a dead credential.
    for action, call in ((_SUBJECT, _get_user), (_SIBLING, _list_tags)):
        code = _poll(
            lambda c=call: _outcome(lambda: c(as_user, user)),
            lambda o: o == "OK",
            timeout_s=_budget_s(ctx, 90.0),
            interval_s=3,
            description=f"the user's own Allow makes {action} effective for the minted key",
        )
        assert code == "OK", (
            f"{action} is Allowed by the user's own inline policy and nothing denies it yet, so the "
            f"real signed call must succeed; expected 'OK', got {code!r}"
        )

    iam.put_group_policy(
        GroupName=group,
        PolicyName=_GROUP_DENY,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": _SUBJECT, "Resource": user_arn}],
        }),
    )
    stored = _group_policy_document(iam, group, _GROUP_DENY)
    assert stored["Statement"][0]["Effect"] == "Deny", (
        f"the group policy must be stored as a Deny before its effect is asserted; GetGroupPolicy "
        f"returned {stored!r}"
    )

    # IAM propagates a policy change eventually: until it settles, successive calls can still be
    # allowed, so the Deny counts as effective only after 5 consecutive refusals.
    denied, _ = _poll(
        _streak(lambda: _outcome(lambda: _get_user(as_user, user)), "AccessDenied"),
        lambda o: o[1] >= 5,
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description=f"the group's explicit Deny refuses {_SUBJECT} for the member",
    )
    assert denied == "AccessDenied", (
        f"{_SUBJECT} is Allowed by the user's own policy and Denied by a policy on a group it belongs "
        f"to, so the real signed call must be refused with exactly AccessDenied; got {denied!r} -- an "
        f"emulator that evaluates only the principal's own policies permits this"
    )
    denied_msg = _denial_message(lambda: _get_user(as_user, user))
    assert denied_msg == _expected_denial(denied_msg, (
        f"User: {user_arn} is not authorized to perform: {_SUBJECT} on resource: user {user} "
        "with an explicit deny in an identity-based policy"
    )), f"expected the exact AccessDenied message AWS returns, got {denied_msg!r}"

    sibling = _outcome(lambda: _list_tags(as_user, user))
    assert sibling == "OK", (
        f"{_SIBLING} is not named by the group's Deny, so it must still succeed while {_SUBJECT} is "
        f"refused; expected 'OK', got {sibling!r} -- an emulator that treats any group Deny as a "
        f"blanket revoke fails here"
    )

    verdict = _simulated(iam, user_arn, user_arn, _SUBJECT)
    assert verdict == "explicitDeny", (
        f"the denial comes from a Deny statement reachable through the group, so the simulator must "
        f"report 'explicitDeny' -- 'implicitDeny' would mean it never aggregated the group's policy; "
        f"got {verdict!r}"
    )

    # Only the membership is removed; the group's Deny stays, proving the group edge carried it.
    iam.remove_user_from_group(GroupName=group, UserName=user)
    groups_now = [
        g["GroupName"]
        for page in iam.get_paginator("list_groups_for_user").paginate(UserName=user)
        for g in page["Groups"]
    ]
    assert group not in groups_now, (
        f"the membership must observably be gone before its effect is asserted; the paginated "
        f"ListGroupsForUser still reports {groups_now!r}"
    )
    restored = _poll(
        lambda: _outcome(lambda: _get_user(as_user, user)),
        lambda o: o == "OK",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description=f"leaving the group restores {_SUBJECT} while the group's Deny still exists",
    )
    assert restored == "OK", (
        f"the group's Deny policy still exists and the user's own Allow never changed, so removing "
        f"the membership alone must restore {_SUBJECT}; expected 'OK', got {restored!r} -- this is "
        f"what proves the group edge, not some account-wide state, carried the Deny"
    )
    surviving = iam.get_group_policy(GroupName=group, PolicyName=_GROUP_DENY)
    assert surviving["PolicyName"] == _GROUP_DENY, (
        f"the Deny must still be attached to the group after the member left, so the restore is "
        f"about the edge and not about the policy disappearing; GetGroupPolicy returned "
        f"{surviving.get('PolicyName')!r}"
    )


def _get_user(client, user):
    return client.get_user(UserName=user)


def _list_tags(client, user):
    return client.list_user_tags(UserName=user)


def _outcome(fn):
    """``"OK"`` on success, else the AWS error code."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") or "NO_ERROR_CODE"
    return "OK"


def _streak(probe, want):
    """A probe returning ``(outcome, consecutive reads equal to want so far)``."""
    count = [0]

    def read():
        outcome = probe()
        count[0] = count[0] + 1 if outcome == want else 0
        return outcome, count[0]

    return read


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded retry with a deadline; raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not happen within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


def _signing_as(ctx, service, key):
    """A client for ``service`` on the same target, signing as the principal that owns ``key``."""
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )


def _group_policy_document(iam, group, policy_name):
    """The group's inline policy document as a dict, read through GetGroupPolicy."""
    doc = iam.get_group_policy(GroupName=group, PolicyName=policy_name)["PolicyDocument"]
    if isinstance(doc, str):
        return json.loads(urllib.parse.unquote(doc))
    return doc


def _simulated(iam, source_arn, resource_arn, action):
    """The simulator's EvalDecision for one action."""
    results = iam.simulate_principal_policy(
        PolicySourceArn=source_arn, ActionNames=[action], ResourceArns=[resource_arn]
    )["EvaluationResults"]
    assert results, (
        f"SimulatePrincipalPolicy must return an evaluation result for {action!r}; "
        f"EvaluationResults was empty"
    )
    return results[0]["EvalDecision"]


def _leave_group(iam, group, user):
    """Teardown-only: the body removes the membership itself, so tolerate it already being gone."""
    try:
        iam.remove_user_from_group(GroupName=group, UserName=user)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _drop_group_policy(iam, group, policy_name):
    """Teardown-only: DeleteGroup refuses a group with inline policies, so this runs before it."""
    try:
        iam.delete_group_policy(GroupName=group, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
