"""sep-policy-composition-sqs-identity-or-queue-policy-each-suffice-denied-with-neither."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-policy-composition-sqs-identity-or-queue-policy-each-suffice-denied-with-neither"
GROUP = "auth_enforcement"
SERVICES = ["iam", "sqs"]


# ===== helpers =====
def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


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


def _client_as(ctx, key_id, secret, service="iam"):
    """A client signing as the minted principal."""
    return ctx.client(service, creds={"aws_access_key_id": key_id, "aws_secret_access_key": secret})


def _refusal(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; a success fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a refusal, but the call succeeded: {result!r}")


def _settle(probe, want, *, description, streak=3, timeout_s=150, interval_s=2):
    """Poll until probe() returns `want` on `streak` consecutive calls; returns every observation.

    IAM is eventually consistent; a streak keeps one lagging replica from reading as steady state.
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
    try:
        iam.delete_user(UserName=user)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
# ===== end helpers =====


def _mint(ctx, iam, prefix, policy=None):
    name = ctx.unique_name(prefix)
    arn = iam.create_user(UserName=name)["User"]["Arn"]
    ctx.on_cleanup(lambda: _purge_user(iam, name))
    if policy is not None:
        iam.put_user_policy(UserName=name, PolicyName="identity", PolicyDocument=policy)
    key = iam.create_access_key(UserName=name)["AccessKey"]
    return name, arn, key


def _types(result):
    return sorted({m.get("SourcePolicyType") for m in result.get("MatchedStatements", [])})


def _drain(sqs, url, want, *, timeout_s=90):
    """Receive until every body in `want` has been seen; return the set seen."""
    seen = set()
    deadline = time.monotonic() + timeout_s
    while not want <= seen and time.monotonic() < deadline:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                     WaitTimeSeconds=5).get("Messages", []):
            seen.add(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return seen


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Same-account SendMessage is granted by either the identity or the queue policy (both messages
    delivered) and denied with neither; the simulator agrees, and clearing the queue policy denies.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
    """
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")
    qname = ctx.unique_name("sim2real-sep-sqs-")[:80]
    url = sqs.create_queue(QueueName=qname, tags={"sim2real": "sep-policy-composition"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    qarn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    ident, ident_arn, ident_key = _mint(ctx, iam, "sim2real-sep-sqs-id-", _policy(
        {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": qarn}))
    res, res_arn, res_key = _mint(ctx, iam, "sim2real-sep-sqs-rp-")
    none, none_arn, none_key = _mint(ctx, iam, "sim2real-sep-sqs-no-")
    queue_policy = _policy({
        "Sid": "ResourcePolicyOnly", "Effect": "Allow", "Principal": {"AWS": res_arn},
        "Action": "sqs:SendMessage", "Resource": qarn,
    })
    _settle(lambda: _outcome(lambda: sqs.set_queue_attributes(
        QueueUrl=url, Attributes={"Policy": queue_policy})), "OK",
        description="SetQueueAttributes Policy naming the new user", streak=1)

    def sim(arn, **kw):
        return _decisions(iam, arn, ["sqs:SendMessage"], [qarn], **kw)["sqs:SendMessage"]

    _settle(lambda: sim(ident_arn, ResourcePolicy=queue_policy)["EvalDecision"], "allowed",
            description="simulator: identity-policy-only user", streak=1)
    s_ident, s_res, s_none = (sim(a, ResourcePolicy=queue_policy) for a in (ident_arn, res_arn, none_arn))
    assert (s_ident["EvalDecision"], _types(s_ident)) == ("allowed", ["IAM Policy"]), f"{s_ident!r}"
    assert (s_res["EvalDecision"], _types(s_res)) == ("allowed", ["Resource Policy"]), f"{s_res!r}"
    assert s_none["EvalDecision"] == "implicitDeny", f"user with neither: {s_none!r}"

    as_ident = _client_as(ctx, ident_key["AccessKeyId"], ident_key["SecretAccessKey"], service="sqs")
    as_res = _client_as(ctx, res_key["AccessKeyId"], res_key["SecretAccessKey"], service="sqs")
    as_none = _client_as(ctx, none_key["AccessKeyId"], none_key["SecretAccessKey"], service="sqs")
    b_ident, b_res, b_none = (f"{who}-{uuid.uuid4().hex}" for who in ("ident", "res", "none"))
    send = lambda c, b: _outcome(lambda: c.send_message(QueueUrl=url, MessageBody=b))  # noqa: E731

    _settle(lambda: send(as_ident, b_ident), "OK", description="identity-only SendMessage", streak=1)
    _settle(lambda: send(as_res, b_res), "OK", description="queue-policy-only SendMessage", streak=1)
    def denied_send(client, user_arn, body):
        got = _refusal(lambda: client.send_message(QueueUrl=url, MessageBody=body))
        want = (
            "AccessDenied",
            f"User: {user_arn} is not authorized to perform: sqs:sendmessage on resource: {qarn} "
            f"because no identity-based policy allows the sqs:sendmessage action",
        )
        return got, want

    denied, want_denied = denied_send(as_none, none_arn, b_none)
    assert denied == want_denied, (
        f"a user granted by neither policy must be refused with exactly AccessDenied; got {denied!r}"
    )
    seen = _drain(sqs, url, {b_ident, b_res}, timeout_s=_budget_s(ctx, 90.0))
    assert {b_ident, b_res} <= seen, f"both granted messages must be delivered; received {seen!r}"
    assert b_none not in seen, f"the refused message must never be delivered; received {seen!r}"
    simulated = {k: v["EvalDecision"] == "allowed" for k, v in
                 (("ident", s_ident), ("res", s_res), ("none", s_none))}
    enforced = {"ident": b_ident in seen, "res": b_res in seen, "none": b_none in seen}
    assert simulated == enforced, f"simulator {simulated!r} disagrees with SQS delivery {enforced!r}"

    # --- Remove only the resource-policy half.
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": ""})
    assert sim(res_arn)["EvalDecision"] == "implicitDeny", "no queue policy, no identity policy"
    b_late = f"late-{uuid.uuid4().hex}"
    _settle(lambda: send(as_res, b_late), "AccessDenied",
            description="queue-policy-only user after the queue policy is cleared", timeout_s=180)
    late, want_late = denied_send(as_res, res_arn, b_late)
    assert late == want_late, (
        f"the queue-policy-only user must be refused exactly once the policy is cleared; got {late!r}"
    )
    b_still = f"still-{uuid.uuid4().hex}"
    assert send(as_ident, b_still) == "OK", "the identity-policy half is independent of the queue policy"
    tail = _drain(sqs, url, {b_still}, timeout_s=_budget_s(ctx, 90.0))
    assert b_still in tail, f"the identity-policy user's message must still be delivered; got {tail!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
