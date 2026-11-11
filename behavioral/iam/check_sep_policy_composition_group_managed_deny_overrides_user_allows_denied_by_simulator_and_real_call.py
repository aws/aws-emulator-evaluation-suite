"""sep-policy-composition-group-managed-deny-overrides-user-allows-denied-by-simulator-and-real-call."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-policy-composition-group-managed-deny-overrides-user-allows-denied-by-simulator-and-real-call"
GROUP = "policy_composition"
SERVICES = ["iam"]


# ===== helpers =====
def _error_code(fn):
    """The captured AWS error code, or a sentinel that cannot be mistaken for one on success."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "UNEXPECTED_SUCCESS"


def _outcome(fn):
    """'OK' when the real signed call succeeds, else its exact AWS error code."""
    code = _error_code(fn)
    return "OK" if code == "UNEXPECTED_SUCCESS" else code


def _refusal(fn):
    """``(code, message)`` of a call real AWS refuses; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it succeeded and returned {result!r}")


def _with_authorization_details(base, message):
    """IAM's access-denied text: ``base`` followed by a pointer to the per-request authorization
    id, the one opaque token read back from the message; the console link names us-east-1."""
    region = "us-east-1"
    marker = "authorization id: "
    auth_id = message.rsplit(marker, 1)[-1] if message and marker in message else "<absent>"
    return (
        f"{base}. Go to https://{region}.console.aws.amazon.com/iam/home?region={region}"
        f"#/authorization-details/{auth_id} for complete details, or call the "
        f"GetRequestAuthorizationDetails API with the following authorization id: {auth_id}"
    )


def _client_as(ctx, key_id, secret, token=None, service="iam"):
    """A client signing AS the minted principal, wired to the same target as every other client."""
    creds = {"aws_access_key_id": key_id, "aws_secret_access_key": secret}
    if token:
        creds["aws_session_token"] = token
    return ctx.client(service, creds=creds)


def _settle(probe, want, *, description, streak=3, timeout_s=150, interval_s=2):
    """Poll until probe() returns `want` on `streak` consecutive calls; return every observation.

    IAM is eventually consistent; a streak keeps one lagging replica from reading as settled."""
    deadline = time.monotonic() + timeout_s
    seen, run = [], 0
    while True:
        got = probe()
        seen.append(got)
        run = run + 1 if got == want else 0
        if run >= streak:
            return seen
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: wanted {want!r} {streak}x in a row within {timeout_s}s; "
                f"last observations {seen[-12:]!r}"
            )
        time.sleep(interval_s)


def _policy(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def _decisions(iam, source_arn, actions, resource_arns, **kw):
    results = iam.simulate_principal_policy(
        PolicySourceArn=source_arn, ActionNames=actions, ResourceArns=resource_arns, **kw
    )["EvaluationResults"]
    return {r["EvalActionName"]: r for r in results}


def _sim_settle(iam, source_arn, actions, resource_arns, want, *, description, **kw):
    """Poll the simulator until every action's EvalDecision equals `want[action]`."""
    last = {}

    def probe():
        nonlocal last
        last = _decisions(iam, source_arn, actions, resource_arns, **kw)
        return {a: last[a]["EvalDecision"] for a in actions}

    _settle(probe, want, description=description, streak=1)
    return last


def _purge_user(iam, user):
    """Undo everything a check may have hung on a user, then delete it."""
    for fn in (
        lambda: [iam.delete_user_policy(UserName=user, PolicyName=p)
                 for p in iam.list_user_policies(UserName=user)["PolicyNames"]],
        lambda: [iam.detach_user_policy(UserName=user, PolicyArn=p["PolicyArn"])
                 for p in iam.list_attached_user_policies(UserName=user)["AttachedPolicies"]],
        lambda: [iam.delete_access_key(UserName=user, AccessKeyId=k["AccessKeyId"])
                 for k in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]],
        lambda: [iam.remove_user_from_group(UserName=user, GroupName=g["GroupName"])
                 for g in iam.list_groups_for_user(UserName=user)["Groups"]],
        lambda: iam.delete_user_permissions_boundary(UserName=user),
    ):
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
    iam.delete_user(UserName=user)
# ===== end helpers =====


def _purge_group(iam, group):
    for fn in (
        lambda: [iam.detach_group_policy(GroupName=group, PolicyArn=p["PolicyArn"])
                 for p in iam.list_attached_group_policies(GroupName=group)["AttachedPolicies"]],
        lambda: [iam.remove_user_from_group(GroupName=group, UserName=u["UserName"])
                 for u in iam.get_group(GroupName=group)["Users"]],
    ):
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
    iam.delete_group(GroupName=group)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A group-attached managed Deny overrides a user's inline and managed Allows: ListUserTags is
    explicitDeny (attributed to the Deny policy) and AccessDenied on real calls while GetUser
    stays allowed; leaving the group restores both views.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
    """
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-sep-deny-")
    group = ctx.unique_name("sim2real-sep-deny-grp-")
    allow_name = ctx.unique_name("sim2real-sep-deny-allow-")
    deny_name = ctx.unique_name("sim2real-sep-deny-deny-")

    # Managed policies first, so LIFO deletes them only after every attachment is gone.
    allow_arn = iam.create_policy(
        PolicyName=allow_name,
        PolicyDocument=_policy({"Effect": "Allow", "Action": "iam:ListUserTags", "Resource": "*"}),
        Description="sim2real managed allow",
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=allow_arn))
    deny_arn = iam.create_policy(
        PolicyName=deny_name,
        PolicyDocument=_policy({"Effect": "Deny", "Action": "iam:ListUserTags", "Resource": "*"}),
        Description="sim2real managed deny",
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=deny_arn))

    user_arn = iam.create_user(UserName=user)["User"]["Arn"]
    ctx.on_cleanup(lambda: _purge_user(iam, user))
    iam.put_user_policy(
        UserName=user,
        PolicyName="inline-allow",
        PolicyDocument=_policy({
            "Effect": "Allow", "Action": ["iam:GetUser", "iam:ListUserTags"], "Resource": user_arn,
        }),
    )
    iam.attach_user_policy(UserName=user, PolicyArn=allow_arn)
    key = iam.create_access_key(UserName=user)["AccessKey"]
    as_user = _client_as(ctx, key["AccessKeyId"], key["SecretAccessKey"])
    actions = ["iam:GetUser", "iam:ListUserTags"]

    # --- Baseline: both Allows effective in BOTH views before anything is broken.
    _sim_settle(iam, user_arn, actions, [user_arn],
                {"iam:GetUser": "allowed", "iam:ListUserTags": "allowed"},
                description="simulator baseline, no deny in play")
    _settle(lambda: _outcome(lambda: as_user.get_user(UserName=user)), "OK",
            description="real GetUser baseline")
    _settle(lambda: _outcome(lambda: as_user.list_user_tags(UserName=user)), "OK",
            description="real ListUserTags baseline (two Allows, no Deny)")

    # --- Break exactly one thing: join a group whose managed policy Denies one action.
    iam.create_group(GroupName=group)
    ctx.on_cleanup(lambda: _purge_group(iam, group))
    iam.attach_group_policy(GroupName=group, PolicyArn=deny_arn)
    iam.add_user_to_group(GroupName=group, UserName=user)

    sim = _sim_settle(iam, user_arn, actions, [user_arn],
                      {"iam:GetUser": "allowed", "iam:ListUserTags": "explicitDeny"},
                      description="simulator once the group Deny reaches the user")
    sources = [m.get("SourcePolicyId", "") for m in sim["iam:ListUserTags"].get("MatchedStatements", [])]
    assert any(deny_name in s for s in sources), (
        f"the explicitDeny must be attributed to the group-attached Deny policy {deny_name!r}; "
        f"matched statements came from {sources!r}"
    )
    _settle(lambda: _outcome(lambda: as_user.list_user_tags(UserName=user)), "AccessDenied",
            description="real ListUserTags once the group Deny reaches the user")
    denied, denied_message = _refusal(lambda: as_user.list_user_tags(UserName=user))
    assert denied == "AccessDenied", (
        f"an explicit Deny overrides the inline AND managed Allow; got {denied!r}"
    )
    expected_message = _with_authorization_details(
        f"User: {user_arn} is not authorized to perform: iam:ListUserTags on resource: user "
        f"{user} with an explicit deny in an identity-based policy: {deny_arn}",
        denied_message,
    )
    assert denied_message == expected_message, (
        f"expected message {expected_message!r}, got {denied_message!r}"
    )
    control = _outcome(lambda: as_user.get_user(UserName=user))
    assert control == "OK", f"the Deny names only ListUserTags; GetUser must still work, got {control!r}"

    simulated = {a: sim[a]["EvalDecision"] == "allowed" for a in actions}
    enforced = {"iam:GetUser": control == "OK", "iam:ListUserTags": denied == "OK"}
    assert simulated == enforced, (
        f"simulator and authorizer disagree on a cross-policy Deny: simulator {simulated!r}, "
        f"real calls {enforced!r}"
    )

    # --- Undo the one break: leaving the group must restore both views.
    iam.remove_user_from_group(GroupName=group, UserName=user)
    _sim_settle(iam, user_arn, actions, [user_arn],
                {"iam:GetUser": "allowed", "iam:ListUserTags": "allowed"},
                description="simulator after leaving the Deny group")
    _settle(lambda: _outcome(lambda: as_user.list_user_tags(UserName=user)), "OK",
            description="real ListUserTags after leaving the Deny group")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
