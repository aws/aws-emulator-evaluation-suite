"""sep-policy-composition-principal-tag-condition-simulated-with-real-tags-denied-on-mismatch."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-policy-composition-principal-tag-condition-simulated-with-real-tags-denied-on-mismatch"
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


def _tag_ctx(value):
    return [{"ContextKeyName": "aws:PrincipalTag/team", "ContextKeyValues": [value],
             "ContextKeyType": "string"}]


def _team_tag(iam, user):
    tags_ = {t["Key"]: t["Value"] for t in iam.list_user_tags(UserName=user)["Tags"]}
    return tags_.get("team")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """aws:PrincipalTag is read from the caller's current tags: retagging the user flips a tag-gated
    call to AccessDenied and back, and the simulator fed the actual tag predicts each outcome.
    Without context, the simulator names aws:PrincipalTag/team in MissingContextValues.
    """
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-sep-ptag-")
    v1, v2 = "blue-" + uuid.uuid4().hex[:6], "red-" + uuid.uuid4().hex[:6]
    user_arn = iam.create_user(UserName=user, Tags=[{"Key": "team", "Value": v1}])["User"]["Arn"]
    ctx.on_cleanup(lambda: _purge_user(iam, user))
    iam.put_user_policy(
        UserName=user, PolicyName="control",
        PolicyDocument=_policy({"Effect": "Allow", "Action": "iam:GetUser", "Resource": user_arn}),
    )
    iam.put_user_policy(
        UserName=user, PolicyName="abac",
        PolicyDocument=_policy({
            "Effect": "Allow", "Action": "iam:ListUserPolicies", "Resource": user_arn,
            "Condition": {"StringEquals": {"aws:PrincipalTag/team": v1}},
        }),
    )
    key = iam.create_access_key(UserName=user)["AccessKey"]
    as_user = _client_as(ctx, key["AccessKeyId"], key["SecretAccessKey"])
    act = ["iam:ListUserPolicies"]
    real = lambda: _outcome(lambda: as_user.list_user_policies(UserName=user))  # noqa: E731

    def sim_with_actual_tag():
        actual = _team_tag(iam, user)
        return _decisions(iam, user_arn, act, [user_arn],
                          ContextEntries=_tag_ctx(actual))["iam:ListUserPolicies"]["EvalDecision"]

    no_ctx = _sim_settle(iam, user_arn, act, [user_arn], {"iam:ListUserPolicies": "implicitDeny"},
                         description="simulator with no principal-tag context")
    assert "aws:PrincipalTag/team" in no_ctx["iam:ListUserPolicies"].get("MissingContextValues", []), (
        f"the simulator must name the key it was not given; got {no_ctx['iam:ListUserPolicies']!r}"
    )

    # --- Tag matches: both views allow.
    _settle(lambda: _outcome(lambda: as_user.get_user(UserName=user)), "OK",
            description="real GetUser positive control")
    _settle(real, "OK", description=f"real ListUserPolicies while tagged team={v1}")
    _settle(sim_with_actual_tag, "allowed", description="simulator fed the user's actual tag",
            streak=1)

    # --- Retag the principal only; no policy or request parameter changes.
    iam.tag_user(UserName=user, Tags=[{"Key": "team", "Value": v2}])
    assert _team_tag(iam, user) == v2, "the retag must read back"
    _settle(real, "AccessDenied", description=f"real ListUserPolicies once retagged team={v2}")
    denied, denied_message = _refusal(lambda: as_user.list_user_policies(UserName=user))
    assert denied == "AccessDenied", f"tag mismatch must be refused exactly; got {denied!r}"
    expected_message = _with_authorization_details(
        f"User: {user_arn} is not authorized to perform: iam:ListUserPolicies on resource: user "
        f"{user} because no identity-based policy allows the iam:ListUserPolicies action",
        denied_message,
    )
    assert denied_message == expected_message, (
        f"expected message {expected_message!r}, got {denied_message!r}"
    )
    mismatch_sim = sim_with_actual_tag()
    assert mismatch_sim == "implicitDeny", (
        f"fed the user's actual tag {v2!r}, the simulator must deny; got {mismatch_sim!r}"
    )
    assert (mismatch_sim == "allowed") == (denied == "OK"), (
        f"simulator {mismatch_sim!r} disagrees with real call {denied!r} after the retag"
    )
    control = _outcome(lambda: as_user.get_user(UserName=user))
    assert control == "OK", f"the unconditioned control must survive the retag; got {control!r}"

    # --- Retag back: both views restore.
    iam.tag_user(UserName=user, Tags=[{"Key": "team", "Value": v1}])
    _settle(real, "OK", description=f"real ListUserPolicies once retagged back to team={v1}")
    assert sim_with_actual_tag() == "allowed", "simulator must allow again with the restored tag"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
