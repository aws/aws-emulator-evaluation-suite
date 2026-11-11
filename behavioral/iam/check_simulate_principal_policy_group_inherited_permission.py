"""simulate-principal-policy-group-inherited-permission."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "simulate-principal-policy-group-inherited-permission"
GROUP = 'policy_simulation'
SERVICES = ['iam']

ALLOW_SQS_SEND = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}],
    }
)
GROUP_INLINE_ALLOW_SQS_RECEIVE = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sqs:ReceiveMessage", "Resource": "*"}],
    }
)


def _poll(fn, pred, *, timeout_s, interval_s, description):
    """Poll fn() until pred(value) or the deadline; raise on timeout so a stall never reads as agreement."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not reached within {timeout_s}s; last observation {val!r}")
        time.sleep(interval_s)
        val = fn()
    return val


def _leave_group(iam, group, user):
    """Teardown-only: the body leaves the group itself, so tolerate it already being gone."""
    try:
        iam.remove_user_from_group(GroupName=group, UserName=user)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _decisions(iam, user_arn, actions):
    return {
        r["EvalActionName"]: r["EvalDecision"]
        for r in iam.simulate_principal_policy(
            PolicySourceArn=user_arn, ActionNames=actions
        )["EvaluationResults"]
    }


@tags("axis:happy-path", "cap:c7", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SimulatePrincipalPolicy for a user with no direct grants includes its group's managed and
    inline policies, and drops them once the user leaves the group (the group keeps its policies).
    """
    iam = ctx.client("iam")
    actions = ["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage"]

    user = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user, Path="/")
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    user_arn = iam.get_user(UserName=user)["User"]["Arn"]

    group = ctx.unique_name("sim2real-behav-group-")
    iam.create_group(GroupName=group, Path="/")
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group))

    managed_arn = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-behav-pol-"), PolicyDocument=ALLOW_SQS_SEND
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=managed_arn))
    iam.attach_group_policy(GroupName=group, PolicyArn=managed_arn)
    ctx.on_cleanup(lambda: iam.detach_group_policy(GroupName=group, PolicyArn=managed_arn))

    inline_name = "sim2real-behav-group-inline"
    iam.put_group_policy(
        GroupName=group, PolicyName=inline_name, PolicyDocument=GROUP_INLINE_ALLOW_SQS_RECEIVE
    )
    ctx.on_cleanup(lambda: iam.delete_group_policy(GroupName=group, PolicyName=inline_name))

    # --- Baseline: the user is in no group yet, so nothing is granted.
    before = _decisions(iam, user_arn, actions)
    for action in actions:
        assert before[action] == "implicitDeny", (
            "a user with no attachments and no group membership must be denied everything; "
            f"{action} got {before[action]!r}"
        )

    # --- Join the group: both the group's managed AND inline policies must now apply.
    iam.add_user_to_group(GroupName=group, UserName=user)
    ctx.on_cleanup(lambda: _leave_group(iam, group, user))
    assert group in [
        g["GroupName"] for g in iam.list_groups_for_user(UserName=user)["Groups"]
    ], "membership must be visible via ListGroupsForUser before simulating"

    joined = _poll(
        lambda: _decisions(iam, user_arn, actions),
        lambda d: d.get("sqs:SendMessage") == "allowed"
        and d.get("sqs:ReceiveMessage") == "allowed",
        timeout_s=60,
        interval_s=3,
        description="the group's managed+inline grants propagate to SimulatePrincipalPolicy after AddUserToGroup",
    )
    assert joined["sqs:SendMessage"] == "allowed", (
        "sqs:SendMessage is granted only by the group's ATTACHED MANAGED policy; expected "
        f"'allowed', got {joined['sqs:SendMessage']!r}"
    )
    assert joined["sqs:ReceiveMessage"] == "allowed", (
        "sqs:ReceiveMessage is granted only by the group's INLINE policy; expected 'allowed', got "
        f"{joined['sqs:ReceiveMessage']!r}"
    )
    assert joined["sqs:DeleteMessage"] == "implicitDeny", (
        "sqs:DeleteMessage is granted by neither group policy, so group inheritance must not become "
        f"a blanket allow; got {joined['sqs:DeleteMessage']!r}"
    )

    # --- Leave the group: inheritance must stop for both grants.
    iam.remove_user_from_group(GroupName=group, UserName=user)
    assert iam.list_groups_for_user(UserName=user)["Groups"] == [], (
        "membership must be gone from ListGroupsForUser after RemoveUserFromGroup"
    )
    left = _poll(
        lambda: _decisions(iam, user_arn, actions),
        lambda d: d.get("sqs:SendMessage") == "implicitDeny"
        and d.get("sqs:ReceiveMessage") == "implicitDeny",
        timeout_s=60,
        interval_s=3,
        description="the group's inherited grants are revoked from SimulatePrincipalPolicy after RemoveUserFromGroup",
    )
    assert left["sqs:SendMessage"] == "implicitDeny", (
        "leaving the group must revoke the inherited managed grant; got "
        f"{left['sqs:SendMessage']!r}"
    )
    assert left["sqs:ReceiveMessage"] == "implicitDeny", (
        "leaving the group must revoke the inherited inline grant; got "
        f"{left['sqs:ReceiveMessage']!r}"
    )

    # The group itself still holds both policies -- the revocation came from the membership edge,
    # not from the policies disappearing.
    assert managed_arn in [
        p["PolicyArn"]
        for p in iam.list_attached_group_policies(GroupName=group)["AttachedPolicies"]
    ], "the group must still hold its managed attachment"
    assert inline_name in iam.list_group_policies(GroupName=group)["PolicyNames"], (
        "the group must still hold its inline policy"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
