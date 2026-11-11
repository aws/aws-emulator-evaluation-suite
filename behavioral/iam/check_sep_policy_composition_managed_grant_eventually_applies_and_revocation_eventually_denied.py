"""sep-policy-composition-managed-grant-eventually-applies-and-revocation-eventually-denied."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-policy-composition-managed-grant-eventually-applies-and-revocation-eventually-denied"
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


def _converge(probe, want, *, description, streak=3, timeout_s=180, interval_s=2):
    """Poll to `want` held `streak` times in a row; return (attempts_to_first_hit, observations)."""
    deadline = time.monotonic() + timeout_s
    seen, run, first = [], 0, None
    while True:
        got = probe()
        seen.append(got)
        if got == want and first is None:
            first = len(seen)
        run = run + 1 if got == want else 0
        if run >= streak:
            return first, seen
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} never converged to {want!r} within {timeout_s}s; "
                f"observations {seen[-15:]!r}"
            )
        time.sleep(interval_s)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Attaching a managed policy eventually allows ListUserTags and detaching it eventually denies
    it again, in simulator and real calls, while an inline-granted GetUser keeps working; changes
    are polled to convergence, not timed, since IAM documents only eventual propagation.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency
    """
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-sep-ec-")
    pol_name = ctx.unique_name("sim2real-sep-ec-grant-")

    grant_arn = iam.create_policy(
        PolicyName=pol_name,
        PolicyDocument=_policy({"Effect": "Allow", "Action": "iam:ListUserTags", "Resource": "*"}),
        Description="sim2real eventual-consistency grant",
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=grant_arn))
    user_arn = iam.create_user(UserName=user)["User"]["Arn"]
    ctx.on_cleanup(lambda: _purge_user(iam, user))
    iam.put_user_policy(
        UserName=user, PolicyName="control",
        PolicyDocument=_policy({"Effect": "Allow", "Action": "iam:GetUser", "Resource": user_arn}),
    )
    key = iam.create_access_key(UserName=user)["AccessKey"]
    as_user = _client_as(ctx, key["AccessKeyId"], key["SecretAccessKey"])
    act = ["iam:ListUserTags"]
    real = lambda: _outcome(lambda: as_user.list_user_tags(UserName=user))  # noqa: E731
    simd = lambda: _decisions(iam, user_arn, act, [user_arn])["iam:ListUserTags"]["EvalDecision"]  # noqa: E731

    # --- Before: control works, the ungranted action is denied in both views.
    _converge(lambda: _outcome(lambda: as_user.get_user(UserName=user)), "OK",
              description="real GetUser positive control")
    before, before_message = _refusal(lambda: as_user.list_user_tags(UserName=user))
    assert before == "AccessDenied", f"ListUserTags is not granted yet; got {before!r}"
    expected_message = _with_authorization_details(
        f"User: {user_arn} is not authorized to perform: iam:ListUserTags on resource: user "
        f"{user} because no identity-based policy allows the iam:ListUserTags action",
        before_message,
    )
    assert before_message == expected_message, (
        f"expected message {expected_message!r}, got {before_message!r}"
    )
    assert simd() == "implicitDeny", "the simulator must deny before the attach"

    # --- Grant: poll both views until the attach has converged.
    iam.attach_user_policy(UserName=user, PolicyArn=grant_arn)
    attached = [p["PolicyArn"] for p in iam.list_attached_user_policies(UserName=user)["AttachedPolicies"]]
    assert grant_arn in attached, f"the attach must read back; got {attached!r}"
    s_first, _ = _converge(simd, "allowed", description="simulator after AttachUserPolicy", streak=2)
    r_first, r_seen = _converge(real, "OK", description="real ListUserTags after AttachUserPolicy")
    assert set(r_seen[: r_first - 1]) <= {"AccessDenied"}, (
        f"before the grant lands the only acceptable outcome is AccessDenied; saw {r_seen!r}"
    )

    # --- Revoke: poll both views until the detach has converged.
    iam.detach_user_policy(UserName=user, PolicyArn=grant_arn)
    _converge(simd, "implicitDeny", description="simulator after DetachUserPolicy", streak=2)
    d_first, d_seen = _converge(real, "AccessDenied", description="real ListUserTags after DetachUserPolicy")
    assert set(d_seen[: d_first - 1]) <= {"OK"}, (
        f"until the revocation lands the only acceptable outcome is the prior grant; saw {d_seen!r}"
    )
    control = _outcome(lambda: as_user.get_user(UserName=user))
    assert control == "OK", f"the inline control is untouched by the detach; got {control!r}"
    print(f"[converge] sim grant attempts={s_first} real grant attempts={r_first} "
          f"real revoke attempts={d_first}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
