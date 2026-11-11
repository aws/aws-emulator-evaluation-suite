"""sep-policy-composition-stringnotequals-missing-sourcevpce-key-deny-applies-denied-by-simulator-and-real-call."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-policy-composition-stringnotequals-missing-sourcevpce-key-deny-applies-denied-by-simulator-and-real-call"
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
    """A client signing AS the minted principal."""
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


def _denial_message(fn):
    """Error.Message of a call real AWS refuses; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Message") or ""
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A StringNotEquals Deny on an absent aws:SourceVpce key applies: explicitDeny with no
    MissingContextValues in the simulator and AccessDenied on the real call; the positive
    StringEquals form evaluates false and the Deny stops applying in both views.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
    """
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-sep-vpce-")
    vpce = "vpce-" + uuid.uuid4().hex[:17]

    user_arn = iam.create_user(UserName=user)["User"]["Arn"]
    ctx.on_cleanup(lambda: _purge_user(iam, user))
    iam.put_user_policy(
        UserName=user, PolicyName="allow",
        PolicyDocument=_policy({"Effect": "Allow", "Action": ["iam:GetUser", "iam:ListUserTags"],
                                "Resource": user_arn}),
    )
    key = iam.create_access_key(UserName=user)["AccessKey"]
    as_user = _client_as(ctx, key["AccessKeyId"], key["SecretAccessKey"])
    actions = ["iam:GetUser", "iam:ListUserTags"]
    list_tags = lambda: _outcome(lambda: as_user.list_user_tags(UserName=user))  # noqa: E731

    _settle(list_tags, "OK", description="baseline real ListUserTags, no Deny in play")

    # --- A Deny guarded by a negated operator on a key absent from the request (no VPC endpoint).
    iam.put_user_policy(
        UserName=user, PolicyName="deny-unless-vpce",
        PolicyDocument=_policy({
            "Effect": "Deny", "Action": "iam:ListUserTags", "Resource": user_arn,
            "Condition": {"StringNotEquals": {"aws:SourceVpce": vpce}},
        }),
    )
    sim = _sim_settle(iam, user_arn, actions, [user_arn],
                      {"iam:GetUser": "allowed", "iam:ListUserTags": "explicitDeny"},
                      description="simulator, aws:SourceVpce absent, StringNotEquals Deny")
    missing = sim["iam:ListUserTags"].get("MissingContextValues", [])
    assert missing == [], (
        "an absent key under a negated operator is DECIDED (condition true), not undecidable, so the "
        f"simulator must not report it missing; got {missing!r}"
    )
    with_ctx = _decisions(iam, user_arn, ["iam:ListUserTags"], [user_arn], ContextEntries=[
        {"ContextKeyName": "aws:SourceVpce", "ContextKeyValues": [vpce], "ContextKeyType": "string"},
    ])["iam:ListUserTags"]["EvalDecision"]
    assert with_ctx == "allowed", (
        f"with aws:SourceVpce == {vpce!r} the StringNotEquals condition is false, so the Deny must "
        f"not apply; simulator said {with_ctx!r}"
    )

    _settle(list_tags, "AccessDenied",
            description="real ListUserTags with no VPC endpoint under the StringNotEquals Deny")
    denied = list_tags()
    assert denied == "AccessDenied", (
        f"the missing-key StringNotEquals Deny must block the real call exactly; got {denied!r}"
    )
    denied_msg = _denial_message(lambda: as_user.list_user_tags(UserName=user))
    expected_msg = _with_authorization_details(
        f"User: {user_arn} is not authorized to perform: iam:ListUserTags on resource: user "
        f"{user} with an explicit deny in an identity-based policy",
        denied_msg,
    )
    assert denied_msg == expected_msg, f"expected message {expected_msg!r}, got {denied_msg!r}"
    control = _outcome(lambda: as_user.get_user(UserName=user))
    assert control == "OK", f"GetUser is outside the Deny and must still work; got {control!r}"
    assert {a: sim[a]["EvalDecision"] == "allowed" for a in actions} == {
        "iam:GetUser": control == "OK", "iam:ListUserTags": denied == "OK"
    }, f"simulator {sim!r} disagrees with real calls GetUser={control!r} ListUserTags={denied!r}"

    # --- Swap ONLY the operator to the positive form: the same absent key now evaluates false.
    iam.put_user_policy(
        UserName=user, PolicyName="deny-unless-vpce",
        PolicyDocument=_policy({
            "Effect": "Deny", "Action": "iam:ListUserTags", "Resource": user_arn,
            "Condition": {"StringEquals": {"aws:SourceVpce": vpce}},
        }),
    )
    _sim_settle(iam, user_arn, actions, [user_arn],
                {"iam:GetUser": "allowed", "iam:ListUserTags": "allowed"},
                description="simulator, aws:SourceVpce absent, positive StringEquals Deny")
    _settle(list_tags, "OK",
            description="real ListUserTags once the Deny's operator is the positive StringEquals")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
