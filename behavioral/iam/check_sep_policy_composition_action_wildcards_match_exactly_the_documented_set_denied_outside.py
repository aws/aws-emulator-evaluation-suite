"""sep-policy-composition-action-wildcards-match-exactly-the-documented-set-denied-outside."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-policy-composition-action-wildcards-match-exactly-the-documented-set-denied-outside"
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


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With `iam:GetUse?` + `iam:List*Keys`, GetUser, ListAccessKeys, ListSSHPublicKeys are allowed
    and GetUserPolicy, ListUserTags denied in simulator and real calls (`?` = one char, `*` = any
    run); adding upper-case `IAM:LISTUSERTAGS` allows ListUserTags (matching is case-insensitive).

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html
    """
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-sep-wild-")
    user_arn = iam.create_user(UserName=user)["User"]["Arn"]
    ctx.on_cleanup(lambda: _purge_user(iam, user))

    def put(actions):
        iam.put_user_policy(
            UserName=user, PolicyName="wild",
            PolicyDocument=_policy({"Effect": "Allow", "Action": actions, "Resource": user_arn}),
        )

    put(["iam:GetUse?", "iam:List*Keys"])
    key = iam.create_access_key(UserName=user)["AccessKey"]
    as_user = _client_as(ctx, key["AccessKeyId"], key["SecretAccessKey"])
    calls = {
        "iam:GetUser": lambda: as_user.get_user(UserName=user),
        "iam:ListAccessKeys": lambda: as_user.list_access_keys(UserName=user),
        "iam:ListSSHPublicKeys": lambda: as_user.list_ssh_public_keys(UserName=user),
        "iam:GetUserPolicy": lambda: as_user.get_user_policy(UserName=user, PolicyName="wild"),
        "iam:ListUserTags": lambda: as_user.list_user_tags(UserName=user),
    }
    actions = list(calls)
    expected = {"iam:GetUser": "allowed", "iam:ListAccessKeys": "allowed",
                "iam:ListSSHPublicKeys": "allowed", "iam:GetUserPolicy": "implicitDeny",
                "iam:ListUserTags": "implicitDeny"}

    sim = _sim_settle(iam, user_arn, actions, [user_arn], expected,
                      description="simulator over the wildcard statement")
    for a in ("iam:GetUserPolicy", "iam:ListUserTags"):
        assert sim[a].get("MatchedStatements", []) == [], (
            f"{a} matches no wildcard, so no statement may be reported matched; got {sim[a]!r}"
        )

    _settle(lambda: _outcome(calls["iam:GetUser"]), "OK",
            description="real GetUser via iam:GetUse?")
    real = {a: _outcome(calls[a]) for a in actions}
    assert real == {"iam:GetUser": "OK", "iam:ListAccessKeys": "OK", "iam:ListSSHPublicKeys": "OK",
                    "iam:GetUserPolicy": "AccessDenied", "iam:ListUserTags": "AccessDenied"}, (
        f"real signed calls under `iam:GetUse?` + `iam:List*Keys` returned {real!r}"
    )
    assert {a: real[a] == "OK" for a in actions} == {a: expected[a] == "allowed" for a in actions}, (
        f"simulator {expected!r} disagrees with the real calls {real!r}"
    )

    # --- Add one upper-case action name: case-insensitive match must flip ListUserTags only.
    put(["iam:GetUse?", "iam:List*Keys", "IAM:LISTUSERTAGS"])
    widened = dict(expected, **{"iam:ListUserTags": "allowed"})
    _sim_settle(iam, user_arn, actions, [user_arn], widened,
                description="simulator once IAM:LISTUSERTAGS is added")
    _settle(lambda: _outcome(calls["iam:ListUserTags"]), "OK",
            description="real ListUserTags via the upper-case action name")
    still, still_message = _refusal(calls["iam:GetUserPolicy"])
    assert still == "AccessDenied", (
        f"GetUserPolicy is still matched by nothing and must stay refused; got {still!r}"
    )
    expected_message = _with_authorization_details(
        f"User: {user_arn} is not authorized to perform: iam:GetUserPolicy on resource: user "
        f"{user} because no identity-based policy allows the iam:GetUserPolicy action",
        still_message,
    )
    assert still_message == expected_message, (
        f"expected message {expected_message!r}, got {still_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
