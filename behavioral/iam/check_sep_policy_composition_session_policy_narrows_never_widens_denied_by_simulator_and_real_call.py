"""sep-policy-composition-session-policy-narrows-never-widens-denied-by-simulator-and-real-call."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-policy-composition-session-policy-narrows-never-widens-denied-by-simulator-and-real-call"
GROUP = "policy_composition"
SERVICES = ["iam"]


def _error_code(fn):
    """The captured AWS error code, or a sentinel that cannot be mistaken for one on success."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "UNEXPECTED_SUCCESS"


def _error_message(fn):
    """The captured AWS error message; a successful call fails the refusal claim."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Message")
    raise AssertionError("the call succeeded where AWS refuses it")


def _outcome(fn):
    """'OK' when the real signed call succeeds, else its exact AWS error code."""
    code = _error_code(fn)
    return "OK" if code == "UNEXPECTED_SUCCESS" else code


def _client_as(ctx, key_id, secret, token=None, service="iam"):
    """A client signing AS the minted principal, wired to the same target as every other client."""
    creds = {"aws_access_key_id": key_id, "aws_secret_access_key": secret}
    if token:
        creds["aws_session_token"] = token
    return ctx.client(service, creds=creds)


def _settle(probe, want, *, description, streak=3, timeout_s=150, interval_s=2):
    """Poll until probe() returns `want` on `streak` CONSECUTIVE calls.

    IAM is eventually consistent and exposes no API that reports a grant as effective, so the
    operation is its own observable. A streak (rather than one hit) keeps a single lagging replica
    from being read as the steady state. Returns every observation, for the failure message.
    """
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
        except ClientError:
            pass
    iam.delete_user(UserName=user)


# IAM's console host for authorization details is fixed to its global partition region.
_DETAILS_URL = "https://us-east-1.console.aws.amazon.com/iam/home?region=us-east-1#/authorization-details/"


def _denial_message(principal_arn, action, resource, why, message, *, details):
    """The exact AccessDenied message AWS writes for this principal, action and resource.

    ``why`` is the policy type AWS names (``identity-based``, ``session``). With ``details``, AWS
    appends a per-request authorization id, read back from the message and placed twice.
    """
    base = (
        f"User: {principal_arn} is not authorized to perform: {action} on resource: {resource} "
        f"because no {why} policy allows the {action} action"
    )
    if not details:
        return base
    auth = (message or "").rsplit(" ", 1)[-1]
    return (
        f"{base}. Go to {_DETAILS_URL}{auth} for complete details, or call the "
        f"GetRequestAuthorizationDetails API with the following authorization id: {auth}"
    )


def _purge_role(iam, role):
    for p in iam.list_role_policies(RoleName=role)["PolicyNames"]:
        try:
            iam.delete_role_policy(RoleName=role, PolicyName=p)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
    iam.delete_role(RoleName=role)


def _assume(sts, role_arn, session_name, *, policy=None, timeout_s=120, interval_s=3):
    """AssumeRole with the bounded AccessDenied retry a just-written trust policy needs."""
    kw = {"RoleArn": role_arn, "RoleSessionName": session_name, "DurationSeconds": 900}
    if policy is not None:
        kw["Policy"] = policy
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sts.assume_role(**kw)["Credentials"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "AccessDenied":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"AssumeRole on {role_arn!r} (session policy: {policy is not None}) failed "
                    f"with {code!r}"
                ) from exc
            time.sleep(interval_s)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A session policy narrows an assumed role but never widens it: real session outcomes equal the
    intersection of the role and session-policy simulations, with exact AccessDenied messages.
    A control session with no session policy matches the role simulation alone.
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    caller_arn = sts.get_caller_identity()["Arn"]
    role = ctx.unique_name("sim2real-sep-sess-")

    role_arn = iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=_policy({
            "Effect": "Allow", "Principal": {"AWS": caller_arn}, "Action": "sts:AssumeRole",
        }),
        Description="sim2real session-policy composition",
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _purge_role(iam, role))
    iam.put_role_policy(
        RoleName=role,
        PolicyName="role-grant",
        PolicyDocument=_policy({
            "Effect": "Allow", "Action": ["iam:GetRole", "iam:ListRoleTags"], "Resource": role_arn,
        }),
    )
    session_policy = _policy({
        "Effect": "Allow", "Action": ["iam:GetRole", "iam:ListRolePolicies"], "Resource": role_arn,
    })
    actions = ["iam:GetRole", "iam:ListRoleTags", "iam:ListRolePolicies"]

    # --- Simulator on the role's own policy.
    role_sim = _sim_settle(
        iam, role_arn, actions, [role_arn],
        {"iam:GetRole": "allowed", "iam:ListRoleTags": "allowed",
         "iam:ListRolePolicies": "implicitDeny"},
        description="simulator on the role policy",
    )
    # --- Simulator on the session policy alone.
    sess_sim = {
        r["EvalActionName"]: r["EvalDecision"]
        for r in iam.simulate_custom_policy(
            PolicyInputList=[session_policy], ActionNames=actions, ResourceArns=[role_arn]
        )["EvaluationResults"]
    }
    assert sess_sim == {"iam:GetRole": "allowed", "iam:ListRoleTags": "implicitDeny",
                        "iam:ListRolePolicies": "allowed"}, (
        f"SimulateCustomPolicy on the session policy alone returned {sess_sim!r}"
    )
    predicted = {a: role_sim[a]["EvalDecision"] == "allowed" and sess_sim[a] == "allowed"
                 for a in actions}
    assert predicted == {"iam:GetRole": True, "iam:ListRoleTags": False,
                         "iam:ListRolePolicies": False}, f"intersection was {predicted!r}"

    calls = {
        "iam:GetRole": lambda c: c.get_role(RoleName=role),
        "iam:ListRoleTags": lambda c: c.list_role_tags(RoleName=role),
        "iam:ListRolePolicies": lambda c: c.list_role_policies(RoleName=role),
    }

    # --- Control session: no session policy, so enforcement must equal the role simulation alone.
    plain = _assume(sts, role_arn, ctx.unique_name("ctl-")[:60])
    as_plain = _client_as(ctx, plain["AccessKeyId"], plain["SecretAccessKey"], plain["SessionToken"])
    _settle(lambda: _outcome(lambda: calls["iam:ListRoleTags"](as_plain)), "OK",
            description="control session: role-granted ListRoleTags")
    control = {a: _outcome(lambda a=a: calls[a](as_plain)) for a in actions}
    assert control == {"iam:GetRole": "OK", "iam:ListRoleTags": "OK",
                       "iam:ListRolePolicies": "AccessDenied"}, (
        f"a session with no session policy must behave exactly as the role policy; got {control!r}"
    )
    assert {a: control[a] == "OK" for a in actions} == {
        a: role_sim[a]["EvalDecision"] == "allowed" for a in actions
    }, f"control session {control!r} disagrees with the role simulation"

    # --- Narrowed session: same role, one extra input -- the session policy.
    narrow_session = ctx.unique_name("sess-")[:60]
    narrow = _assume(sts, role_arn, narrow_session, policy=session_policy)
    as_narrow = _client_as(ctx, narrow["AccessKeyId"], narrow["SecretAccessKey"],
                           narrow["SessionToken"])
    _settle(lambda: _outcome(lambda: calls["iam:GetRole"](as_narrow)), "OK",
            description="narrowed session: GetRole, allowed by role AND session policy")
    narrowed = {a: _outcome(lambda a=a: calls[a](as_narrow)) for a in actions}
    assert narrowed["iam:ListRoleTags"] == "AccessDenied", (
        "the role allows ListRoleTags but the session policy omits it, so the session must be "
        f"refused with exactly AccessDenied (narrowing); got {narrowed['iam:ListRoleTags']!r}"
    )
    assert narrowed["iam:ListRolePolicies"] == "AccessDenied", (
        "the session policy grants ListRolePolicies but the role does not, so the session must be "
        f"refused with exactly AccessDenied (a session policy never widens); got "
        f"{narrowed['iam:ListRolePolicies']!r}"
    )
    narrow_arn = f"arn:aws:sts::{role_arn.split(':')[4]}:assumed-role/{role}/{narrow_session}"
    for action, why in (("iam:ListRoleTags", "session"), ("iam:ListRolePolicies", "identity-based")):
        message = _error_message(lambda a=action: calls[a](as_narrow))
        want = _denial_message(narrow_arn, action, f"role {role}", why, message, details=True)
        assert message == want, f"{action} AccessDenied message: expected {want!r}, got {message!r}"
    enforced = {a: narrowed[a] == "OK" for a in actions}
    assert enforced == predicted, (
        f"real session outcomes {narrowed!r} are not the intersection the two simulations predict "
        f"{predicted!r}"
    )
    # The control session is still unrestricted in the same instant: the narrowing is per-session.
    again = _outcome(lambda: calls["iam:ListRoleTags"](as_plain))
    assert again == "OK", f"the control session must be unaffected by a sibling's session policy; got {again!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
