"""sep-policy-composition-boundary-caps-identity-allow-denied-by-simulator-and-real-call."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-policy-composition-boundary-caps-identity-allow-denied-by-simulator-and-real-call"
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
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
    iam.delete_user(UserName=user)
# ===== end helpers =====


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A permissions boundary intersects the identity policy, and SimulatePrincipalPolicy and a real
    signed call agree action by action: a boundary-omitted action is implicitDeny and AccessDenied,
    an action inside both is allowed and succeeds, and removing the boundary flips both views."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-sep-bnd-")
    boundary_name = ctx.unique_name("sim2real-sep-bnd-cap-")

    boundary_arn = iam.create_policy(
        PolicyName=boundary_name,
        PolicyDocument=_policy({"Effect": "Allow", "Action": "iam:GetUser", "Resource": "*"}),
        Description="sim2real boundary: iam:GetUser only",
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=boundary_arn))

    # Born bounded: the boundary exists before any grant, so no replica can ever see the grant
    # without the cap.
    user_arn = iam.create_user(UserName=user, PermissionsBoundary=boundary_arn)["User"]["Arn"]
    ctx.on_cleanup(lambda: _purge_user(iam, user))
    got_boundary = iam.get_user(UserName=user)["User"].get("PermissionsBoundary", {})
    assert got_boundary.get("PermissionsBoundaryArn") == boundary_arn, (
        f"the user must carry the boundary it was created with; got {got_boundary!r}"
    )

    # The identity policy allows BOTH actions; the boundary allows only the first.
    iam.put_user_policy(
        UserName=user,
        PolicyName="identity-get-and-list-keys",
        PolicyDocument=_policy({
            "Effect": "Allow",
            "Action": ["iam:GetUser", "iam:ListAccessKeys"],
            "Resource": user_arn,
        }),
    )
    key = iam.create_access_key(UserName=user)["AccessKey"]
    as_user = _client_as(ctx, key["AccessKeyId"], key["SecretAccessKey"])

    actions = ["iam:GetUser", "iam:ListAccessKeys"]

    # --- Oracle A: the simulator.
    sim = _sim_settle(
        iam, user_arn, actions, [user_arn],
        {"iam:GetUser": "allowed", "iam:ListAccessKeys": "implicitDeny"},
        description="simulator: GetUser allowed, ListAccessKeys capped by the boundary",
    )
    pb_get = sim["iam:GetUser"].get("PermissionsBoundaryDecisionDetail", {})
    pb_list = sim["iam:ListAccessKeys"].get("PermissionsBoundaryDecisionDetail", {})
    assert pb_get.get("AllowedByPermissionsBoundary") is True, (
        f"the boundary allows iam:GetUser, so the simulator must say so; got {pb_get!r}"
    )
    assert pb_list.get("AllowedByPermissionsBoundary") is False, (
        "the boundary omits iam:ListAccessKeys, so the simulator must attribute the denial to the "
        f"boundary (AllowedByPermissionsBoundary False); got {pb_list!r}"
    )

    # --- Oracle B: the real signed calls. The allowed action is the positive control that proves
    # the key and the identity policy are live before the denial is read.
    _settle(lambda: _outcome(lambda: as_user.get_user(UserName=user)), "OK",
            description="real GetUser by the bounded user (inside identity AND boundary)")
    _settle(lambda: _outcome(lambda: as_user.list_access_keys(UserName=user)), "AccessDenied",
            description="real ListAccessKeys by the bounded user (identity allows, boundary omits)")
    denied, denied_message = _refusal(lambda: as_user.list_access_keys(UserName=user))
    assert denied == "AccessDenied", (
        f"an action outside the boundary must be refused with exactly AccessDenied; got {denied!r}"
    )
    expected_message = _with_authorization_details(
        f"User: {user_arn} is not authorized to perform: iam:ListAccessKeys on resource: user "
        f"{user} because no permissions boundary allows the iam:ListAccessKeys action",
        denied_message,
    )
    assert denied_message == expected_message, (
        f"expected message {expected_message!r}, got {denied_message!r}"
    )
    still = _outcome(lambda: as_user.get_user(UserName=user))
    assert still == "OK", f"the in-boundary control must keep succeeding; got {still!r}"

    # --- The relation: simulator verdict == enforcement outcome, per action.
    simulated = {a: sim[a]["EvalDecision"] == "allowed" for a in actions}
    enforced = {"iam:GetUser": still == "OK", "iam:ListAccessKeys": denied == "OK"}
    assert simulated == enforced, (
        f"simulator and authorizer disagree under a boundary: simulator {simulated!r}, "
        f"real calls {enforced!r}"
    )

    # --- Remove the ONE thing that caused the denial: both views must flip together.
    iam.delete_user_permissions_boundary(UserName=user)
    lifted = _sim_settle(
        iam, user_arn, actions, [user_arn],
        {"iam:GetUser": "allowed", "iam:ListAccessKeys": "allowed"},
        description="simulator after the boundary is removed",
    )
    assert "PermissionsBoundaryDecisionDetail" not in lifted["iam:ListAccessKeys"] or (
        lifted["iam:ListAccessKeys"]["PermissionsBoundaryDecisionDetail"].get(
            "AllowedByPermissionsBoundary") is not False
    ), f"no boundary remains, so none may be blamed; got {lifted['iam:ListAccessKeys']!r}"
    _settle(lambda: _outcome(lambda: as_user.list_access_keys(UserName=user)), "OK",
            description="real ListAccessKeys once the boundary is removed")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
