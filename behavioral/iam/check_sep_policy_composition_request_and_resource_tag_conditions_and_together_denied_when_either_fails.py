"""sep-policy-composition-request-and-resource-tag-conditions-and-together-denied-when-either-fails."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-policy-composition-request-and-resource-tag-conditions-and-together-denied-when-either-fails"
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


def _ctx(owner, env):
    return [
        {"ContextKeyName": "aws:ResourceTag/owner", "ContextKeyValues": [owner],
         "ContextKeyType": "string"},
        {"ContextKeyName": "aws:RequestTag/env", "ContextKeyValues": [env],
         "ContextKeyType": "string"},
        {"ContextKeyName": "aws:TagKeys", "ContextKeyValues": ["env"],
         "ContextKeyType": "stringList"},
    ]


def _tags_of(iam, user):
    return {t["Key"]: t["Value"] for t in iam.list_user_tags(UserName=user)["Tags"]}


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """aws:ResourceTag and aws:RequestTag in one Condition block AND together: TagUser is denied
    when either fails, a refused write leaves tags unchanged, and the simulator predicts each case.
    Retagging the second target to the matching owner flips its outcome to allowed.
    """
    iam = ctx.client("iam")
    caller = ctx.unique_name("sim2real-sep-tagc-")
    target_x = ctx.unique_name("sim2real-sep-tagx-")
    target_y = ctx.unique_name("sim2real-sep-tagy-")
    owner_x, owner_y = "own-" + uuid.uuid4().hex[:8], "own-" + uuid.uuid4().hex[:8]

    x_arn = iam.create_user(UserName=target_x, Tags=[{"Key": "owner", "Value": owner_x}])["User"]["Arn"]
    ctx.on_cleanup(lambda: _purge_user(iam, target_x))
    y_arn = iam.create_user(UserName=target_y, Tags=[{"Key": "owner", "Value": owner_y}])["User"]["Arn"]
    ctx.on_cleanup(lambda: _purge_user(iam, target_y))
    caller_arn = iam.create_user(UserName=caller)["User"]["Arn"]
    ctx.on_cleanup(lambda: _purge_user(iam, caller))
    iam.put_user_policy(
        UserName=caller, PolicyName="tag-gate",
        PolicyDocument=_policy(
            {"Effect": "Allow", "Action": "iam:GetUser", "Resource": caller_arn},
            {"Effect": "Allow", "Action": "iam:TagUser", "Resource": [x_arn, y_arn],
             "Condition": {
                 "StringEquals": {"aws:ResourceTag/owner": owner_x, "aws:RequestTag/env": "dev"},
                 "ForAllValues:StringEquals": {"aws:TagKeys": ["env"]},
             }},
        ),
    )
    key = iam.create_access_key(UserName=caller)["AccessKey"]
    as_caller = _client_as(ctx, key["AccessKeyId"], key["SecretAccessKey"])
    tag = lambda u, v: _outcome(  # noqa: E731
        lambda: as_caller.tag_user(UserName=u, Tags=[{"Key": "env", "Value": v}]))

    # --- Simulator over the three combinations.
    _sim_settle(iam, caller_arn, ["iam:TagUser"], [x_arn], {"iam:TagUser": "allowed"},
                description="simulator: owner matches AND env=dev", ContextEntries=_ctx(owner_x, "dev"))
    sim = {
        "match": "allowed",
        "wrong_request_tag": _decisions(iam, caller_arn, ["iam:TagUser"], [x_arn],
                                        ContextEntries=_ctx(owner_x, "prod"))["iam:TagUser"]["EvalDecision"],
        "wrong_resource_tag": _decisions(iam, caller_arn, ["iam:TagUser"], [y_arn],
                                         ContextEntries=_ctx(owner_y, "dev"))["iam:TagUser"]["EvalDecision"],
    }
    assert sim == {"match": "allowed", "wrong_request_tag": "implicitDeny",
                   "wrong_resource_tag": "implicitDeny"}, f"simulator verdicts {sim!r}"

    # --- Real calls.
    _settle(lambda: _outcome(lambda: as_caller.get_user(UserName=caller)), "OK",
            description="real GetUser positive control")
    _settle(lambda: tag(target_x, "dev"), "OK", description="real TagUser env=dev on owner=X target")
    assert _tags_of(iam, target_x).get("env") == "dev", f"env=dev must read back: {_tags_of(iam, target_x)!r}"

    def no_allow(target):
        return (
            f"User: {caller_arn} is not authorized to perform: iam:TagUser on resource: user "
            f"{target} because no identity-based policy allows the iam:TagUser action"
        )

    wrong_req, wrong_req_message = _refusal(
        lambda: as_caller.tag_user(UserName=target_x, Tags=[{"Key": "env", "Value": "prod"}]))
    assert wrong_req == "AccessDenied", f"env=prod violates aws:RequestTag; got {wrong_req!r}"
    expected_message = _with_authorization_details(no_allow(target_x), wrong_req_message)
    assert wrong_req_message == expected_message, (
        f"expected message {expected_message!r}, got {wrong_req_message!r}"
    )
    assert _tags_of(iam, target_x).get("env") == "dev", (
        f"the refused write must not change the tag; got {_tags_of(iam, target_x)!r}"
    )
    wrong_res, wrong_res_message = _refusal(
        lambda: as_caller.tag_user(UserName=target_y, Tags=[{"Key": "env", "Value": "dev"}]))
    assert wrong_res == "AccessDenied", f"owner=Y violates aws:ResourceTag; got {wrong_res!r}"
    expected_message = _with_authorization_details(no_allow(target_y), wrong_res_message)
    assert wrong_res_message == expected_message, (
        f"expected message {expected_message!r}, got {wrong_res_message!r}"
    )
    assert "env" not in _tags_of(iam, target_y), (
        f"the refused write must leave no env tag; got {_tags_of(iam, target_y)!r}"
    )
    enforced = {"match": "allowed", "wrong_request_tag": "allowed" if wrong_req == "OK" else "implicitDeny",
                "wrong_resource_tag": "allowed" if wrong_res == "OK" else "implicitDeny"}
    assert enforced == sim, f"simulator {sim!r} disagrees with enforcement {enforced!r}"

    # --- Change ONLY the second target's resource tag: its outcome must flip in both views.
    iam.tag_user(UserName=target_y, Tags=[{"Key": "owner", "Value": owner_x}])
    flipped = _decisions(iam, caller_arn, ["iam:TagUser"], [y_arn],
                         ContextEntries=_ctx(owner_x, "dev"))["iam:TagUser"]["EvalDecision"]
    assert flipped == "allowed", f"simulator for retagged target: {flipped!r}"
    _settle(lambda: tag(target_y, "dev"), "OK",
            description="real TagUser env=dev once the target is retagged owner=X")
    assert _tags_of(iam, target_y).get("env") == "dev", f"write must land: {_tags_of(iam, target_y)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
